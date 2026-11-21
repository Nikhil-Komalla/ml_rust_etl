#!/usr/bin/env python3
"""
Shopping Sessions: DuckDB pipeline.

Reads  $DATA_DIR    (default /data)
Writes $OUTPUT_DIR  (default /output): user_daily/ and campaign_daily/ as Parquet
Temp   $SCRATCH_DIR (default /scratch)
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import glob
import json
import os
import sys
import tempfile
import time

try:
    import resource
except ImportError:
    resource = None

import duckdb

MS_SECOND = 1_000
MS_DAY = 86_400_000
MS_SESSION_GAP = 1_800_000
MS_CLICK_REACH = 604_800_000


def parse_manifest_iso_ms(value: str) -> int:
    """Parse an F1 UTC ISO-8601 timestamp string to epoch milliseconds."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    days = (dt.date() - datetime(1970, 1, 1, tzinfo=timezone.utc).date()).days
    secs = dt.hour * 3600 + dt.minute * 60 + dt.second
    return days * MS_DAY + secs * MS_SECOND


def sql_str(s: str) -> str:
    """Escape a string literal for DuckDB SQL."""
    return "'" + s.replace("'", "''") + "'"


def csv_files(data_dir: str, *parts: str) -> list[str]:
    """Return sorted CSV file paths normalized with forward slashes."""
    pattern = os.path.join(data_dir, *parts)
    return [p.replace("\\", "/") for p in sorted(glob.glob(pattern))]


def file_has_cr(path: str) -> bool:
    """Return True if a file contains any raw ASCII CR (0x0D) byte."""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                return False
            if b"\r" in chunk:
                return True


def partition_files_by_cr(paths: list[str], ncpu: int) -> tuple[list[str], list[str]]:
    """Split CSV files into CR-free files (DuckDB read_csv) and CR-containing files (Python)."""
    if not paths:
        return [], []
    if len(paths) == 1:
        return ([], paths) if file_has_cr(paths[0]) else (paths, [])
    workers = max(1, min(ncpu, len(paths)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        flags = list(pool.map(file_has_cr, paths))
    clean = [p for p, has_cr in zip(paths, flags) if not has_cr]
    dirty = [p for p, has_cr in zip(paths, flags) if has_cr]
    return clean, dirty


def parse_cr_line(
    raw: bytes, expected_cols: int, required_non_null_indices: tuple[int, ...]
) -> tuple[str | None, ...] | None:
    """Parse one LF-terminated raw line per rules.md CSV dialect."""
    if not raw:
        return None
    parts = raw.split(b",")
    if len(parts) != expected_cols:
        return None
    out: list[str | None] = []
    for idx, field in enumerate(parts):
        if b'"' in field:
            if len(field) >= 2 and field[0] == 34 and field[-1] == 34 and b'"' not in field[1:-1]:
                inner = field[1:-1]
            else:
                return None
        else:
            inner = field
        if not inner:
            if idx in required_non_null_indices:
                return None
            out.append(None)
        else:
            try:
                out.append(inner.decode("utf-8"))
            except UnicodeDecodeError:
                return None
    return tuple(out)


def parse_cr_file_batches(
    path: str,
    expected_cols: int,
    required_non_null_indices: tuple[int, ...],
    batch_size: int = 50_000,
):
    """Stream exact LF-delimited validated rows from a CR-containing CSV file."""
    with open(path, "rb") as f:
        buf = b""
        skipped_header = False
        batch: list[tuple[str | None, ...]] = []
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            data = buf + chunk
            lines = data.split(b"\n")
            buf = lines.pop()
            start = 0
            if not skipped_header:
                if lines:
                    start = 1
                    skipped_header = True
                else:
                    continue
            for raw in lines[start:]:
                parsed = parse_cr_line(raw, expected_cols, required_non_null_indices)
                if parsed is not None:
                    batch.append(parsed)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
        if buf and skipped_header:
            parsed = parse_cr_line(buf, expected_cols, required_non_null_indices)
            if parsed is not None:
                batch.append(parsed)
        if batch:
            yield batch


def register_csv_source(
    con: duckdb.DuckDBPyConnection,
    view_name: str,
    paths: list[str],
    col_names: list[str],
    required_non_null_indices: tuple[int, ...],
    ncpu: int,
) -> None:
    """Register a TEMP VIEW enforcing exact rules.md CSV dialect on all files."""
    clean_files, cr_files = partition_files_by_cr(paths, ncpu)
    n_cols = len(col_names)

    queries: list[str] = []
    if clean_files:
        file_list_sql = "[" + ", ".join(sql_str(p) for p in clean_files) + "]"
        raw_cols = ", ".join(f"'c{i}': 'VARCHAR'" for i in range(n_cols)) + ", '_extra': 'VARCHAR'"
        select_exprs = ", ".join(
            f"unquote_csv_field(c{i}) AS {name}" for i, name in enumerate(col_names)
        )
        valid_checks = " AND ".join(f"valid_csv_field(c{i})" for i in range(n_cols))
        non_null_checks = "".join(
            f" AND c{idx} <> '' AND c{idx} <> '\"\"'" for idx in required_non_null_indices
        )
        queries.append(
            f"""
            SELECT {select_exprs}
            FROM read_csv(
                {file_list_sql},
                delim = ',',
                quote = '',
                escape = '',
                comment = '',
                new_line = '\\n',
                header = false,
                skip = 1,
                auto_detect = false,
                null_padding = true,
                strict_mode = false,
                ignore_errors = true,
                nullstr = [chr(10)],
                columns = {{{raw_cols}}}
            )
            WHERE _extra IS NULL AND {valid_checks}{non_null_checks}
            """
        )

    if cr_files:
        cr_table = f"{view_name}_cr"
        col_defs = ", ".join(f"{name} VARCHAR" for name in col_names)
        con.execute(f"CREATE TEMP TABLE {cr_table} ({col_defs})")
        placeholders = ", ".join(["?"] * n_cols)
        insert_sql = f"INSERT INTO {cr_table} VALUES ({placeholders})"
        for path in cr_files:
            for batch in parse_cr_file_batches(path, n_cols, required_non_null_indices):
                con.executemany(insert_sql, batch)
        queries.append(f"SELECT {', '.join(col_names)} FROM {cr_table}")

    if not queries:
        null_cols = ", ".join(f"NULL::VARCHAR AS {name}" for name in col_names)
        con.execute(f"CREATE TEMP VIEW {view_name} AS SELECT {null_cols} WHERE false")
    elif len(queries) == 1:
        con.execute(f"CREATE TEMP VIEW {view_name} AS {queries[0]}")
    else:
        con.execute(f"CREATE TEMP VIEW {view_name} AS {queries[0]} UNION ALL {queries[1]}")


def define_macros(con: duckdb.DuckDBPyConnection) -> None:
    """Define exact CSV dialect, timestamp, price, and UTC date SQL macros."""
    con.execute(
        """
        CREATE TEMP MACRO valid_csv_field(s) AS (
            s IS NOT NULL AND (
                strpos(s, '"') = 0
                OR (
                    length(s) >= 2
                    AND substr(s, 1, 1) = '"'
                    AND substr(s, length(s), 1) = '"'
                    AND strpos(substr(s, 2, length(s) - 2), '"') = 0
                )
            )
        );

        CREATE TEMP MACRO unquote_csv_field(s) AS (
            NULLIF(
                CASE
                    WHEN length(s) >= 2 AND substr(s, 1, 1) = '"' THEN substr(s, 2, length(s) - 2)
                    ELSE s
                END,
                ''
            )
        );

        CREATE TEMP MACRO parse_f1_ms(s) AS (
            CASE
                WHEN s IS NOT NULL
                     AND strlen(s) = 20
                     AND ends_with(s, 'Z')
                     AND strftime(try_cast(substr(s, 1, 19) AS TIMESTAMP), '%Y-%m-%dT%H:%M:%SZ') = s
                THEN epoch_ms(try_cast(substr(s, 1, 19) AS TIMESTAMP))
                ELSE NULL
            END
        );

        CREATE TEMP MACRO parse_ts_ms(s) AS (
            CASE
                WHEN s IS NULL OR s = '' THEN NULL
                WHEN strlen(s) = 20
                     AND ends_with(s, 'Z')
                     AND strftime(try_cast(substr(s, 1, 19) AS TIMESTAMP), '%Y-%m-%dT%H:%M:%SZ') = s
                THEN epoch_ms(try_cast(substr(s, 1, 19) AS TIMESTAMP))
                WHEN ltrim(s, '0123456789') = ''
                THEN try_cast(COALESCE(NULLIF(ltrim(s, '0'), ''), '0') AS BIGINT)
                WHEN strlen(s) = 25
                     AND substr(s, 20, 1) IN ('+', '-')
                     AND substr(s, 23, 1) = ':'
                     AND ltrim(substr(s, 21, 2) || substr(s, 24, 2), '0123456789') = ''
                     AND substr(s, 21, 2) <= '23'
                     AND substr(s, 24, 2) <= '59'
                     AND strftime(try_cast(substr(s, 1, 19) AS TIMESTAMP), '%Y-%m-%dT%H:%M:%S') = substr(s, 1, 19)
                THEN epoch_ms(try_cast(substr(s, 1, 19) AS TIMESTAMP))
                     - (CASE WHEN substr(s, 20, 1) = '+' THEN 1 ELSE -1 END) * (
                         try_cast(substr(s, 21, 2) AS BIGINT) * 3600
                         + try_cast(substr(s, 24, 2) AS BIGINT) * 60
                     ) * 1000
                ELSE NULL
            END
        );

        CREATE TEMP MACRO parse_price_cents(s) AS (
            CASE
                WHEN s IS NOT NULL
                     AND s <> ''
                     AND ltrim(s, '0123456789') = ''
                     AND try_cast(COALESCE(NULLIF(ltrim(s, '0'), ''), '0') AS BIGINT) BETWEEN 1 AND 10000000
                THEN try_cast(COALESCE(NULLIF(ltrim(s, '0'), ''), '0') AS BIGINT)
                ELSE NULL
            END
        );

        CREATE TEMP MACRO ms_to_utc_date(ms) AS (
            DATE '1970-01-01' + CAST(
                CASE
                    WHEN ms >= 0 THEN ms // 86400000
                    ELSE -((-ms + 86399999) // 86400000)
                END AS INTEGER
            )
        );
        """
    )


def build_link_map(
    con: duckdb.DuckDBPyConnection, data_dir: str, scratch_dir: str, ncpu: int
) -> None:
    """Compute transitive connected components named by byte-wise smallest ID."""
    link_files = csv_files(data_dir, "links", "*.csv")
    register_csv_source(con, "links_raw", link_files, ["user_id_a", "user_id_b"], (0, 1), ncpu)

    con.execute(
        """
        CREATE TEMP TABLE link_edges AS
        SELECT DISTINCT
            LEAST(user_id_a, user_id_b) AS u,
            GREATEST(user_id_a, user_id_b) AS v
        FROM links_raw
        WHERE user_id_a <> user_id_b
        """
    )
    edge_count = con.execute("SELECT COUNT(*) FROM link_edges").fetchone()[0]
    if edge_count == 0:
        con.execute("CREATE TEMP TABLE link_map (raw_uid VARCHAR, canonical_uid VARCHAR)")
        con.execute("DROP TABLE link_edges")
        return

    con.execute(
        """
        CREATE TEMP TABLE link_nodes AS
        SELECT
            uid,
            (row_number() OVER (ORDER BY uid) - 1)::INTEGER AS nid
        FROM (
            SELECT u AS uid FROM link_edges
            UNION
            SELECT v AS uid FROM link_edges
        ) t
        """
    )
    num_nodes = con.execute("SELECT COUNT(*) FROM link_nodes").fetchone()[0]

    parent = list(range(num_nodes))
    cur = con.execute(
        """
        SELECT n1.nid, n2.nid
        FROM link_edges e
        JOIN link_nodes n1 ON e.u = n1.uid
        JOIN link_nodes n2 ON e.v = n2.uid
        """
    )
    while True:
        batch = cur.fetchmany(100_000)
        if not batch:
            break
        for u, v in batch:
            while parent[u] != u:
                parent[u] = parent[parent[u]]
                u = parent[u]
            while parent[v] != v:
                parent[v] = parent[parent[v]]
                v = parent[v]
            if u < v:
                parent[v] = u
            elif v < u:
                parent[u] = v

    for i in range(num_nodes):
        parent[i] = parent[parent[i]]

    roots_csv = os.path.join(scratch_dir, "link_roots.csv")
    with open(roots_csv, "w", encoding="utf-8", newline="\n") as f:
        f.write("nid,root_nid\n")
        for i in range(num_nodes):
            r = parent[i]
            if r != i:
                f.write(f"{i},{r}\n")

    roots_sql_path = sql_str(roots_csv.replace("\\", "/"))
    con.execute(
        f"""
        CREATE TEMP TABLE link_map AS
        SELECT n_raw.uid AS raw_uid, n_root.uid AS canonical_uid
        FROM read_csv(
            {roots_sql_path},
            header = true,
            auto_detect = false,
            columns = {{'nid': 'INTEGER', 'root_nid': 'INTEGER'}}
        ) r
        JOIN link_nodes n_raw ON r.nid = n_raw.nid
        JOIN link_nodes n_root ON r.root_nid = n_root.nid
        """
    )
    os.remove(roots_csv)
    con.execute("DROP TABLE link_nodes")
    con.execute("DROP TABLE link_edges")


def clean_parquet_dir(directory: str) -> None:
    """Create output subdirectory and remove stale parquet files."""
    os.makedirs(directory, exist_ok=True)
    for p in glob.glob(os.path.join(directory, "*.parquet")):
        os.remove(p)


def main() -> None:
    t0 = time.perf_counter()
    data_dir = os.environ.get("DATA_DIR", "/data")
    out_dir = os.environ.get("OUTPUT_DIR", "/output")
    scratch_dir = os.environ.get("SCRATCH_DIR")
    if not scratch_dir:
        scratch_dir = "/scratch" if os.path.isdir("/scratch") else tempfile.gettempdir()

    ncpu = int(os.environ.get("NCPU", os.cpu_count() or 1))
    mem_gb = int(os.environ.get("MEM_GB", "8"))
    profile = os.environ.get("PROFILE", "0") == "1"

    duckdb_tmp = os.path.join(scratch_dir, "duckdb_tmp")
    os.makedirs(duckdb_tmp, exist_ok=True)

    con = duckdb.connect()
    con.execute(f"SET threads = {ncpu}")
    con.execute(f"SET memory_limit = '{max(1, int(mem_gb * 0.8))}GB'")
    con.execute(f"SET temp_directory = {sql_str(duckdb_tmp)}")
    con.execute("SET preserve_insertion_order = false")
    con.execute("SET TimeZone = 'UTC'")

    with open(os.path.join(data_dir, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    window_start_ms = parse_manifest_iso_ms(manifest["window_start"])
    window_end_ms = parse_manifest_iso_ms(manifest["window_end"])
    click_window_start_ms = window_start_ms - MS_CLICK_REACH

    define_macros(con)
    t_startup = time.perf_counter()

    # Stage 1: Lookups
    register_csv_source(
        con,
        "products_raw",
        csv_files(data_dir, "products.csv"),
        ["product_id", "category"],
        (0, 1),
        ncpu,
    )
    con.execute("CREATE TEMP TABLE products AS SELECT product_id, category FROM products_raw")

    register_csv_source(
        con,
        "campaigns_raw",
        csv_files(data_dir, "campaigns.csv"),
        ["campaign_id", "channel"],
        (0, 1),
        ncpu,
    )
    con.execute("CREATE TEMP TABLE campaigns AS SELECT campaign_id, channel FROM campaigns_raw")
    t_lookups = time.perf_counter()

    # Stage 2: Transitive identity linking
    build_link_map(con, data_dir, scratch_dir, ncpu)
    t_links = time.perf_counter()

    # Stage 3: Events (parse -> dedup before validation -> validate -> drop late -> map person)
    register_csv_source(
        con,
        "events_raw",
        csv_files(data_dir, "events", "*.csv"),
        ["event_id", "user_id", "ts", "ingest_ts", "event_type", "product_id", "price_cents"],
        (0,),
        ncpu,
    )
    con.execute(
        """
        CREATE TEMP VIEW events_dedup AS
        SELECT
            event_id,
            min(ingest_ts_ms) AS ingest_ts_ms,
            arg_min(
                struct_pack(u := user_id, t := ts, et := event_type, p := product_id, pr := price_cents),
                ingest_ts_ms
            ) AS rec
        FROM (
            SELECT
                event_id,
                user_id,
                ts,
                parse_f1_ms(ingest_ts) AS ingest_ts_ms,
                event_type,
                product_id,
                price_cents
            FROM events_raw
        ) s
        WHERE ingest_ts_ms IS NOT NULL
        GROUP BY event_id
        """
    )
    con.execute(
        f"""
        CREATE TEMP VIEW events_valid AS
        SELECT
            COALESCE(lm.canonical_uid, v.user_id) AS person_id,
            v.event_id,
            v.ts_ms,
            v.product_id,
            v.purchase_cents,
            v.is_purchase
        FROM (
            SELECT
                event_id,
                rec.u AS user_id,
                ts_ms,
                ingest_ts_ms,
                rec.p AS product_id,
                CASE
                    WHEN rec.et = 'purchase' THEN parse_price_cents(rec.pr)
                    ELSE 0::BIGINT
                END AS purchase_cents,
                CASE WHEN rec.et = 'purchase' THEN 1::BIGINT ELSE 0::BIGINT END AS is_purchase
            FROM (
                SELECT
                    event_id,
                    ingest_ts_ms,
                    rec,
                    parse_ts_ms(rec.t) AS ts_ms
                FROM events_dedup
                WHERE rec.u IS NOT NULL
                  AND rec.et IN ('view', 'cart', 'purchase')
                  AND rec.p IS NOT NULL
                  AND (rec.et <> 'purchase' OR parse_price_cents(rec.pr) IS NOT NULL)
            ) parsed
            WHERE ts_ms IS NOT NULL
              AND ts_ms >= {window_start_ms}
              AND ts_ms < {window_end_ms}
              AND ingest_ts_ms - ts_ms <= {MS_DAY}
        ) v
        LEFT JOIN link_map lm ON v.user_id = lm.raw_uid
        """
    )
    t_events_prep = time.perf_counter()

    # Stage 4: Sessionize surviving events & materialize sessions + user_daily
    con.execute(
        f"""
        CREATE TEMP TABLE events_sess AS
        SELECT
            person_id,
            SUM(is_new) OVER (
                PARTITION BY person_id
                ORDER BY ts_ms, event_id
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            ) AS sess_num,
            ts_ms,
            product_id,
            purchase_cents,
            is_purchase
        FROM (
            SELECT
                person_id,
                event_id,
                ts_ms,
                product_id,
                purchase_cents,
                is_purchase,
                CASE
                    WHEN prev_ts IS NULL OR ts_ms - prev_ts > {MS_SESSION_GAP} THEN 1::BIGINT
                    ELSE 0::BIGINT
                END AS is_new
            FROM (
                SELECT
                    person_id,
                    event_id,
                    ts_ms,
                    product_id,
                    purchase_cents,
                    is_purchase,
                    LAG(ts_ms) OVER (PARTITION BY person_id ORDER BY ts_ms, event_id) AS prev_ts
                FROM events_valid
            ) lagged
        ) flagged
        """
    )
    con.execute(
        """
        CREATE TEMP TABLE sessions AS
        SELECT
            person_id,
            sess_num,
            MIN(ts_ms) AS session_start,
            ms_to_utc_date(MIN(ts_ms)) AS day,
            COUNT(*)::BIGINT AS event_count,
            SUM(purchase_cents)::BIGINT AS revenue_cents,
            MAX(is_purchase)::BIGINT AS has_purchase
        FROM events_sess
        GROUP BY person_id, sess_num
        """
    )
    con.execute(
        """
        CREATE TEMP TABLE user_daily AS
        WITH top_cats AS (
            SELECT
                person_id,
                day,
                category AS top_category
            FROM (
                SELECT
                    e.person_id,
                    s.day,
                    COALESCE(p.category, 'unknown') AS category,
                    SUM(e.purchase_cents)::BIGINT AS cat_rev
                FROM events_sess e
                JOIN sessions s
                  ON e.person_id = s.person_id AND e.sess_num = s.sess_num
                LEFT JOIN products p
                  ON e.product_id = p.product_id
                WHERE e.is_purchase = 1
                GROUP BY e.person_id, s.day, category
            ) agg
            QUALIFY row_number() OVER (
                PARTITION BY person_id, day
                ORDER BY cat_rev DESC, category ASC
            ) = 1
        ),
        base AS (
            SELECT
                person_id AS user_id,
                day,
                COUNT(*)::BIGINT AS sessions,
                SUM(event_count)::BIGINT AS events,
                SUM(revenue_cents)::BIGINT AS revenue_cents
            FROM sessions
            GROUP BY person_id, day
        )
        SELECT
            b.user_id::VARCHAR AS user_id,
            b.day::DATE AS day,
            b.sessions::BIGINT AS sessions,
            b.events::BIGINT AS events,
            b.revenue_cents::BIGINT AS revenue_cents,
            tc.top_category::VARCHAR AS top_category
        FROM base b
        LEFT JOIN top_cats tc
          ON b.user_id = tc.person_id AND b.day = tc.day
        """
    )
    con.execute("DROP TABLE events_sess")
    t_sess_ud = time.perf_counter()

    # Stage 5: Clicks (parse -> dedup -> validate -> map person)
    register_csv_source(
        con,
        "clicks_raw",
        csv_files(data_dir, "clicks", "*.csv"),
        ["click_id", "user_id", "campaign_id", "ts"],
        (0,),
        ncpu,
    )
    con.execute(
        f"""
        CREATE TEMP TABLE valid_clicks AS
        SELECT
            COALESCE(lm.canonical_uid, c.user_id) AS person_id,
            c.click_id,
            c.campaign_id,
            c.ts_ms
        FROM (
            SELECT
                click_id,
                rec.u AS user_id,
                rec.c AS campaign_id,
                parse_ts_ms(rec.t) AS ts_ms
            FROM (
                SELECT
                    click_id,
                    any_value(struct_pack(u := user_id, c := campaign_id, t := ts)) AS rec
                FROM clicks_raw
                GROUP BY click_id
            ) dedup
            WHERE rec.u IS NOT NULL
        ) c
        JOIN campaigns cp ON c.campaign_id = cp.campaign_id
        LEFT JOIN link_map lm ON c.user_id = lm.raw_uid
        WHERE c.ts_ms IS NOT NULL
          AND c.ts_ms >= {click_window_start_ms}
          AND c.ts_ms < {window_end_ms}
        """
    )
    t_clicks = time.perf_counter()

    # Stage 6: Attribution (credit via ASOF + assists via merged intervals & rank subtraction)
    con.execute(
        f"""
        CREATE TEMP TABLE campaign_daily AS
        WITH credit_clicks AS (
            SELECT
                person_id,
                ts_ms,
                arg_min(campaign_id, click_id) AS campaign_id
            FROM valid_clicks
            GROUP BY person_id, ts_ms
        ),
        credited_sessions AS (
            SELECT
                CASE
                    WHEN c.ts_ms IS NOT NULL AND s.session_start - c.ts_ms <= {MS_CLICK_REACH}
                    THEN c.campaign_id
                    ELSE 'organic'
                END AS campaign_id,
                s.day,
                s.has_purchase,
                s.revenue_cents
            FROM sessions s
            ASOF LEFT JOIN credit_clicks c
              ON s.person_id = c.person_id AND s.session_start >= c.ts_ms
        ),
        credited_daily AS (
            SELECT
                campaign_id,
                day,
                COUNT(*)::BIGINT AS sessions,
                SUM(has_purchase)::BIGINT AS purchasing_sessions,
                SUM(revenue_cents)::BIGINT AS revenue_cents
            FROM credited_sessions
            GROUP BY campaign_id, day
        ),
        distinct_click_times AS (
            SELECT DISTINCT person_id, campaign_id, ts_ms
            FROM valid_clicks
        ),
        click_intervals AS (
            SELECT
                person_id,
                campaign_id,
                MIN(ts_ms) AS iv_start,
                MAX(ts_ms) + {MS_CLICK_REACH} AS iv_end
            FROM (
                SELECT
                    person_id,
                    campaign_id,
                    ts_ms,
                    SUM(is_new) OVER (
                        PARTITION BY person_id, campaign_id
                        ORDER BY ts_ms
                        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                    ) AS grp
                FROM (
                    SELECT
                        person_id,
                        campaign_id,
                        ts_ms,
                        CASE
                            WHEN prev_ts IS NULL OR ts_ms - prev_ts > {MS_CLICK_REACH} THEN 1::BIGINT
                            ELSE 0::BIGINT
                        END AS is_new
                    FROM (
                        SELECT
                            person_id,
                            campaign_id,
                            ts_ms,
                            LAG(ts_ms) OVER (PARTITION BY person_id, campaign_id ORDER BY ts_ms) AS prev_ts
                        FROM distinct_click_times
                    ) l
                ) f
            ) g
            GROUP BY person_id, campaign_id, grp
        ),
        user_day_bounds AS (
            SELECT
                person_id,
                day,
                MIN(session_start) AS min_start,
                MAX(session_start) AS max_start,
                COUNT(*)::BIGINT AS day_sessions
            FROM sessions
            GROUP BY person_id, day
        ),
        sessions_ranked AS (
            SELECT
                person_id,
                day,
                session_start,
                row_number() OVER (PARTITION BY person_id, day ORDER BY session_start)::BIGINT AS rk
            FROM sessions
        ),
        interval_day_overlaps AS (
            SELECT
                iv.person_id,
                iv.campaign_id,
                b.day,
                iv.iv_start,
                iv.iv_end,
                b.min_start,
                b.max_start,
                b.day_sessions
            FROM click_intervals iv
            JOIN user_day_bounds b
              ON iv.person_id = b.person_id
             AND iv.iv_start <= b.max_start
             AND iv.iv_end >= b.min_start
        ),
        assist_full AS (
            SELECT campaign_id, day, day_sessions AS cnt
            FROM interval_day_overlaps
            WHERE iv_start <= min_start AND iv_end >= max_start
        ),
        assist_partial_raw AS (
            SELECT person_id, campaign_id, day, iv_start, iv_end
            FROM interval_day_overlaps
            WHERE NOT (iv_start <= min_start AND iv_end >= max_start)
        ),
        assist_partial AS (
            SELECT
                o.campaign_id,
                o.day,
                (COALESCE(sr_r.rk, 0::BIGINT) - COALESCE(sr_l.rk, 0::BIGINT)) AS cnt
            FROM assist_partial_raw o
            ASOF LEFT JOIN sessions_ranked sr_r
              ON o.person_id = sr_r.person_id
             AND o.day = sr_r.day
             AND o.iv_end >= sr_r.session_start
            ASOF LEFT JOIN sessions_ranked sr_l
              ON o.person_id = sr_l.person_id
             AND o.day = sr_l.day
             AND (o.iv_start - 1) >= sr_l.session_start
        ),
        assisted_daily AS (
            SELECT
                campaign_id,
                day,
                SUM(cnt)::BIGINT AS assisted_sessions
            FROM (
                SELECT campaign_id, day, cnt FROM assist_full
                UNION ALL
                SELECT campaign_id, day, cnt FROM assist_partial WHERE cnt > 0
            ) u
            GROUP BY campaign_id, day
            HAVING SUM(cnt) > 0
        )
        SELECT
            COALESCE(cr.campaign_id, a.campaign_id)::VARCHAR AS campaign_id,
            CASE
                WHEN COALESCE(cr.campaign_id, a.campaign_id) = 'organic' THEN 'organic'
                ELSE cp.channel
            END::VARCHAR AS channel,
            COALESCE(cr.day, a.day)::DATE AS day,
            COALESCE(cr.sessions, 0::BIGINT)::BIGINT AS sessions,
            COALESCE(cr.purchasing_sessions, 0::BIGINT)::BIGINT AS purchasing_sessions,
            COALESCE(cr.revenue_cents, 0::BIGINT)::BIGINT AS revenue_cents,
            COALESCE(a.assisted_sessions, 0::BIGINT)::BIGINT AS assisted_sessions
        FROM credited_daily cr
        FULL OUTER JOIN assisted_daily a
          ON cr.campaign_id = a.campaign_id AND cr.day = a.day
        LEFT JOIN campaigns cp
          ON COALESCE(cr.campaign_id, a.campaign_id) = cp.campaign_id
        """
    )
    t_attr = time.perf_counter()

    # Stage 7: Write Parquet outputs
    ud_dir = os.path.join(out_dir, "user_daily")
    cd_dir = os.path.join(out_dir, "campaign_daily")
    clean_parquet_dir(ud_dir)
    clean_parquet_dir(cd_dir)

    ud_out = os.path.join(ud_dir, "part-0.parquet").replace("\\", "/")
    cd_out = os.path.join(cd_dir, "part-0.parquet").replace("\\", "/")
    con.execute(f"COPY user_daily TO {sql_str(ud_out)} (FORMAT parquet)")
    con.execute(f"COPY campaign_daily TO {sql_str(cd_out)} (FORMAT parquet)")
    t_write = time.perf_counter()

    if profile:
        rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if resource else -1
        print(
            f"PROFILE startup={t_startup - t0:.3f}s lookups={t_lookups - t_startup:.3f}s "
            f"links={t_links - t_lookups:.3f}s events={t_events_prep - t_links:.3f}s "
            f"sessionize={t_sess_ud - t_events_prep:.3f}s clicks={t_clicks - t_sess_ud:.3f}s "
            f"attribute={t_attr - t_clicks:.3f}s write={t_write - t_attr:.3f}s "
            f"total={t_write - t0:.3f}s ru_maxrss_kb={rss_kb}"
        )


if __name__ == "__main__":
    main()

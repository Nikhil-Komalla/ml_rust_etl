# Shopping Sessions Engine — High-Throughput Parallel CSV → Entity Resolution → Windowed Aggregation → Parquet in Rust

A standalone, ~17,800-line Rust columnar execution engine (`shopping-sessions`) originally built for the Databricks Buildathon Shopping Sessions track and designed as a general-purpose, zero-runtime-overhead template for **large-scale noisy CSV ingestion, transitive entity resolution, deterministic deduplication, per-entity temporal/state segmentation, sliding-window attribution, and direct Apache Parquet output**.

Beyond e-commerce telemetry, this exact five-primitive architecture maps directly onto **high-throughput computational materials science workflows**—specifically unifying millions of **first-principles Density Functional Theory (DFT)** calculations (VASP, Quantum ESPRESSO, GPAW, CP2K, FHI-aims) and **Machine Learning Interatomic Potential (MLIP)** simulations (MACE, CHGNet, M3GNet, NequIP, Allegro, SevenNet, EquiformerV2, DeePMD, MatterSim) across **catalysis, solar/photovoltaics, batteries, and semiconductor defect engineering**.

---

## Table of Contents

1. [What This Engine Does & Design Philosophy](#1-what-this-engine-does--design-philosophy)
2. [Quick Start: Build, Run, Test & Profile](#2-quick-start-build-run-test--profile)
   - [Native Build & Unit Tests](#native-build--unit-tests)
   - [Docker & Makefile Workflows](#docker--makefile-workflows)
   - [Runtime Environment Variables](#runtime-environment-variables)
   - [Input Directory Contract](#input-directory-contract)
   - [Output Schema (`user_daily` & `campaign_daily`)](#output-schema-user_daily--campaign_daily)
   - [Reading Built-in Telemetry (`PROFILE=1` / `PROFILE_DETAIL=1`)](#reading-built-in-telemetry-profile1--profile_detail1)
3. [Engine Architecture & Codebase Map](#3-engine-architecture--codebase-map)
   - [End-to-End Execution Pipeline](#end-to-end-execution-pipeline)
   - [Module Reference (`src/`)](#module-reference-src)
4. [Generalizing to Any Data-Intensive Problem (The Rosetta Stone)](#4-generalizing-to-any-data-intensive-problem-the-rosetta-stone)
5. [Computational Materials Science, DFT & MLIP Workflows](#5-computational-materials-science-dft--mlip-workflows)
   - [5.1 Why Computational Materials Pipelines Hit the Exact Same Bottlenecks](#51-why-computational-materials-pipelines-hit-the-exact-same-bottlenecks)
   - [5.2 Recommended Two-Tier Architecture (Extract → Rust Engine → Python/DuckDB Analysis)](#52-recommended-two-tier-architecture-extract--rust-engine--pythonduckdb-analysis)
   - [5.3 Catalysis & Electrocatalysis Workflows](#53-catalysis--electrocatalysis-workflows)
   - [5.4 Solar / Photovoltaics & Optoelectronics](#54-solar--photovoltaics--optoelectronics)
   - [5.5 Batteries & Solid-State Electrolytes](#55-batteries--solid-state-electrolytes)
   - [5.6 Semiconductors, Point Defects & Electronic Devices](#56-semiconductors-point-defects--electronic-devices)
6. [Developer Playbook: Extending the Rust Engine to Your Scientific Schema](#6-developer-playbook-extending-the-rust-engine-to-your-scientific-schema)
   - [Step A — Encode Domain Quantities in Fixed-Point Integers (`pipeline.rs`, `parse.rs`)](#step-a--encode-domain-quantities-in-fixed-point-integers-pipeline.rs-parse.rs)
   - [Step B — Leverage `CompactKey64` & `Hex128` for Structure Hashes & Material IDs (`csv.rs`)](#step-b--leverage-compactkey64--hex128-for-structure-hashes--material-ids-csv.rs)
   - [Step C — Customize Canonical Selection in Disjoint Set Union (`links.rs`)](#step-c--customize-canonical-selection-in-disjoint-set-union-links.rs)
   - [Step D — Implement Fidelity-Aware Dedup Before Validation (`pipeline.rs`)](#step-d--implement-fidelity-aware-dedup-before-validation-pipeline.rs)
   - [Step E — Swap Temporal Gaps for Reaction Coordinates, Voltage Windows, or Hop Bursts (`pipeline.rs`)](#step-e--swap-temporal-gaps-for-reaction-coordinates-voltage-windows-or-hop-bursts-pipeline.rs)
   - [Step F — Add Scientific Parquet Columns Without Heavy Dependencies (`parquet_out.rs`)](#step-f--add-scientific-parquet-columns-without-heavy-dependencies-parquet_out.rs)
7. [End-to-End Worked Example: Active-Learning Catalysis & Battery Screening](#7-end-to-end-worked-example-active-learning-catalysis--battery-screening)
   - [Sample Input Files](#sample-input-files)
   - [Downstream DuckDB / Polars Queries on Parquet Outputs](#downstream-duckdb--polars-queries-on-parquet-outputs)
8. [Systems & HPC Performance Notes](#8-systems--hpc-performance-notes)
9. [Troubleshooting & Verification](#9-troubleshooting--verification)

---

## 1. What This Engine Does & Design Philosophy

Most Python/Pandas/PySpark/DuckDB pipelines spend >85% of wall-clock time on object boxing, string hash tables, Python/JVM serialization, full-table shuffles, and Parquet encoder overhead when processing **tens of millions of semi-dirty CSV records with cyclic/chained equivalence graphs and temporal window joins**.

This engine replaces the entire stack with a **zero-dependency (no Arrow/DataFusion/Polars at runtime) native Rust binary** built on five domain-agnostic systems primitives:

1. **Strict SIMD CSV Scanning (`src/csv.rs`)**: Zero-copy `mmap` (`MAP_PRIVATE` + `MADV_SEQUENTIAL`) with `pread`/`posix_fadvise` fallback, `pclmulqdq` branchless quote-parity calculation, AVX2 comma/newline bitmask extraction, strict UTF-8 & malformed-quote filtering, and SSE4.1/AVX2 fused ID encoding (`CompactKey64`).
2. **Concurrent Lock-Free Transitive Entity Resolution (`src/links.rs`)**: Builds a global Disjoint Set Union (Union-Find via lock-free atomic CAS) over arbitrary many-to-many edge lists (`links/*.csv`), supporting 400+ hop chains, huge hub components, repeated/self edges, and deterministic canonical ID selection—overlapped concurrently while `events/*.csv` is parsed.
3. **Cache-Partitioned Dedup-Before-Validation (`src/pipeline.rs`)**: Shards primary records by record ID across 256 L2-resident shards (plus 64 shards for 32-char hex IDs) and resolves duplicates *before* filtering invalid/unconverged rows (preserving exact "earliest/highest-priority copy wins, even if invalid" semantics).
4. **L1/L2-Resident Per-Entity CSR, Radix/Bitonic Sort, Segmentation & Sliding-Window Attribution (`src/pipeline.rs`)**: Scatters deduplicated primary records and secondary trigger/anchor records into `P_PERSON = 256` person partitions, interns canonical entities into cache-resident hash tables, sorts with AVX2 bitonic networks (`<= 128` items) or 21-bit radix/bucket sort, segments into monotonic gap-bounded episodes ("sessions"), and computes two-pointer sliding-window attribution + multi-camp assists.
5. **Direct Native Apache Parquet Writer (`src/parquet_out.rs`)**: Emits compliant `PAR1` binary files (`user_daily/part-*.parquet`, `campaign_daily/part-0.parquet`) directly from raw slices using a lightweight hand-written Thrift `TCompactProtocol` encoder (`ThriftBuf`)—using the `parquet` crate strictly in `[dev-dependencies]` for roundtrip unit verification.

---

## 2. Quick Start: Build, Run, Test & Profile

### Native Build & Unit Tests

Requirements: Rust toolchain (`rustc` / `cargo`, edition `2021`, targeting `x86_64` with AVX2 + PCLMULQDQ; works cleanly on Intel Haswell+/Xeon or AMD Zen2+, and falls back gracefully in scalar paths on non-AVX2 builds).

```bash
# Release build (matches Dockerfile flags, LTO=fat, codegen-units=1, panic=abort, strip=true)
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+pclmulqdq" \
  cargo build --release --locked

# Run all 28 release-mode unit tests (codecs, CSV edge cases, DateCache, DSU, radix/bitonic sort, end-to-end Parquet roundtrips)
RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+pclmulqdq" \
  cargo test --release --locked --offline
```

Run directly against any dataset directory on local disk:

```bash
mkdir -p /tmp/my_out
DATA_DIR=/path/to/dataset OUTPUT_DIR=/tmp/my_out NCPU=8 PROFILE=1 PROFILE_DETAIL=1 \
  ./target/release/shopping-sessions
```

### Docker & Makefile Workflows

The [Dockerfile](Dockerfile) builds a minimal multi-stage `debian:bookworm-slim` runtime image executing `/app/shopping-sessions` directly (`CMD ["/app/shopping-sessions"]`, non-root uid `1000`, no shell startup tax unless invoked via [run.sh](run.sh)).

```bash
make build                               # docker buildx build --platform linux/amd64 --load -t shopping-sessions:latest .
make fixtures                            # Run containerized binary on all edge-case fixtures in fixtures/
make dev                                 # Generate 1M-event dev dataset (requires `generate` binary on PATH)
make run-dev                             # Run container with scorer limits (--cpus 8 --memory 24g --network none --read-only)
make check-dev ANSWER=/path/to/answer    # Diff Parquet outputs against expected CSV/Parquet via scripts/compare.py
```

On Apple Silicon (`arm64`) hosts, pass `PLATFORM=linux/arm64` for local loops (see [Makefile](Makefile)). Use [scripts/docker_run.sh](scripts/docker_run.sh) to mirror strict container constraints (`--network none --read-only --tmpfs /tmp:rw,size=64m --pids-limit 4096 --user 1000:1000`).

### Runtime Environment Variables

Configured in [`src/main.rs`](src/main.rs) and [`src/pipeline.rs`](src/pipeline.rs):

| Variable | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `/data` | Read-only input root containing `manifest.json`, `products.csv`, `campaigns.csv`, `events/`, `clicks/`, `links/`. |
| `OUTPUT_DIR` | `/output` | Writable directory where `user_daily/*.parquet` and `campaign_daily/part-0.parquet` are written (stale `.parquet` files are cleaned automatically via `clean_parquet_dir`). |
| `SCRATCH_DIR` / `TMPDIR` / `HOME` | `/scratch` | Used by container entrypoint [run.sh](run.sh) / [Dockerfile](Dockerfile) when `/` is read-only. |
| `NCPU` | host `available_parallelism()` | Worker thread count across `CsvSource`, `build_link_map`, dedup workers, and Stage 5 Parquet writers (`clamped 1..63`). |
| `PROFILE` | unset (`0`) | Set `PROFILE=1` to print wall-clock stage breakdown (`PROFILE ...`) and peak `VmHWM` memory usage. |
| `PROFILE_DETAIL` | unset (`0`) | Set `PROFILE=1 PROFILE_DETAIL=1` for per-phase CPU sums (`PROFILE_DETAIL`) and cycle-attributed micro-counters (`PROFILE_MICRO`). |

### Input Directory Contract

Every CSV directory supports **sharded inputs** (one or many `*.csv` files of varying size, including header-only empty shards):

```text
DATA_DIR/
├── manifest.json          # {"window_start": "2026-10-01T00:00:00Z", "window_end": "2026-10-15T00:00:00Z"}
├── products.csv           # product_id,category
├── campaigns.csv          # campaign_id,channel
├── links/*.csv            # user_id_a,user_id_b (undirected equivalence pairs)
├── events/*.csv           # event_id,user_id,ts,ingest_ts,event_type,product_id,price_cents
└── clicks/*.csv           # click_id,user_id,campaign_id,ts
```

**CSV dialect enforced in `src/csv.rs`**:
- UTF-8 strictly validated; `\n` terminates records (`\r` is preserved as data and rejects trailing numeric/timestamp tokens cleanly).
- Balanced double quotes wrapping *entire* fields (`"u1"` → `u1`, `""` → null/empty). Partial/unbalanced quotes, empty lines, or wrong column counts `!= K` are dropped at scan time.
- Supported timestamps (`src/parse.rs`): UTC ISO-8601 F1 (`2026-10-03T23:58:10Z`), timezone-offset ISO-8601 F2 (`2026-10-03T19:58:10-04:00`), and variable-length ASCII epoch milliseconds F3 (`1791071890000`).

### Output Schema (`user_daily` & `campaign_daily`)

Written directly by [`src/parquet_out.rs`](src/parquet_out.rs):

**1. `$OUTPUT_DIR/user_daily/part-<wid>.parquet`** (1 file per worker with non-zero rows; `part-0.parquet` emitted if empty):

| Column | Parquet Physical Type | Logical Type | Nullable | Definition |
|---|---|---|---|---|
| `user_id` | `BYTE_ARRAY` | `UTF8` | Required | Canonical entity ID (byte-wise smallest ID in the resolved DSU component). |
| `day` | `INT32` | `DATE` | Required | UTC days since Unix epoch of session start. |
| `sessions` | `INT32` | — | Required | Count of distinct episodes (`gap > 30 min` between consecutive distinct timestamps) starting on `day`. |
| `events` | `INT32` | — | Required | Count of valid, deduplicated, non-late events belonging to those sessions. |
| `revenue_cents` | `INT64` | — | Required | Sum of positive integer magnitudes (`price_cents`) across those sessions. |
| `top_category` | `BYTE_ARRAY` | `UTF8` | Optional | Category with highest total magnitude on `(user_id, day)` (byte-wise smallest on tie); `null` if zero positive magnitude. |

**2. `$OUTPUT_DIR/campaign_daily/part-0.parquet`**:

| Column | Parquet Physical Type | Logical Type | Nullable | Definition |
|---|---|---|---|---|
| `campaign_id` | `BYTE_ARRAY` | `UTF8` | Required | Lookup campaign ID (or `"organic"` when no prior anchor falls within `[session_start - reach, session_start]`). |
| `channel` | `BYTE_ARRAY` | `UTF8` | Required | Group/channel from `campaigns.csv` (or `"organic"`). |
| `day` | `INT32` | `DATE` | Required | UTC days since Unix epoch of credited/assisted session start. |
| `sessions` | `INT64` | — | Required | Sessions attributed to this `campaign_id` (latest timestamp, byte-wise smallest `click_id` tie-break). |
| `purchasing_sessions` | `INT64` | — | Required | Attributed sessions containing at least one positive-magnitude event. |
| `revenue_cents` | `INT64` | — | Required | Total magnitude across attributed sessions. |
| `assisted_sessions` | `INT64` | — | Required | Distinct sessions where this `campaign_id` had ≥1 qualifying anchor in reach window (`0` for `"organic"`). |

### Reading Built-in Telemetry (`PROFILE=1` / `PROFILE_DETAIL=1`)

Running with `PROFILE=1 PROFILE_DETAIL=1` outputs three diagnostic lines:

- `PROFILE ...`: Wall-clock durations of sequential/barrier boundaries (`lookups`, `events_parse`, `events_dedup`, `sessionize_attr_ud`, `camp_write`, `total`, `vm_hwm_kb`). Note `links=0.0000s` and `clicks=0.0000s` indicate `build_link_map` and click ingestion completed overlapped behind `events_parse`/`events_dedup`.
- `PROFILE_DETAIL ...`: Thread-summed CPU seconds across all workers (`links_w`, `ev_io_scan_cpu`, `ev_dec_cpu`, `cl_cpu`, `dedup_p1_cpu`, `dedup_p2_cpu`, `s5_ev_csr_cpu`, `s5_cl_csr_cpu`, `s5_sort_cpu`, `s5_sess_attr_cpu`, `s5_ud_cpu`). Note `PROFILE_DETAIL=1` adds per-batch/per-row `rdtsc()` instrumentation inside `PD=true` generic paths; always measure wall-clock benchmarks without `PROFILE_DETAIL=1`.
- `PROFILE_MICRO ...`: Classification counts (`f1`, `f3`, `oth`), fast-path vs fallback record counts (`fb37`, `fuhex`, `eb37`, `ib37`, `hex`, `egen`, `igen`, `purch`), Bloom/slot hit statistics (`b_hit`, `b_slot`, `b_miss`), and `LinkMap` table footprints (`lm_kb`).

---

## 3. Engine Architecture & Codebase Map

### End-to-End Execution Pipeline

```text
  manifest.json + products.csv + campaigns.csv
         │
         ▼  load_lookups() ──► Dense fast arrays (prod_fast, camp_fast) + FlatKvSlot
         │
         ├───────────────────────────────────────────────────────────┐
         ▼ (threads 0..link_threads)                                 ▼ (threads link_threads..N-1)
  build_link_map(links/*.csv)                               run_parse_events_worker(events/*.csv)
   • 32-shard lock-free DSU + CAS                            • CsvSource (mmap zero-copy + pad tail)
   • HugeBuf 6-lane LinkGroup64 + Bloom                      • AVX2 batched line/comma/UTF-8 scan
   • OnceLock publish LinkMap                                • Fast F1/F2/F3 + Base37/Hex128 encode
         │                                                   • Scatter -> 256 P_DEDUP / 64 P_HEX_DEDUP
         └──────────────────────────┬────────────────────────────────┘
                                    ▼ Barrier: wait_gate(&lm_gate) & wait_gate(&ev_gate)
         ┌──────────────────────────┴────────────────────────────────┐
         ▼ Phase 2 (before/with tail)                                ▼ Phase 3 (lock-free work stealing)
  clicks/*.csv ──► ClLinkPipe ──► 256 P_PERSON shards       dedup_p1 (min ingest_ts; invalid kept!)
                                                                     │
                                                                     ▼ dedup_p2: EvLinkPipe + LinkMap
                                                                256 P_PERSON shards
         └──────────────────────────┬────────────────────────────────┘
                                    ▼ Stage 5 (run_stage5 across 256 L1/L2 shards)
                          1. Intern entities into cache-resident p_slots (CSR offsets)
                          2. AVX2 bitonic (<=128) or 21-bit radix sort per entity
                          3. Monotonic segmentation + two-pointer credit/assist attribution
                          4. Direct UserDailyWriter/*.parquet + CampDailyAcc ──► write_campaign_daily
                          5. fast_exit -> flush stdout/stderr + _exit(0)
```

### Module Reference (`src/`)

| File | LOC | Responsibility & Key Symbols |
|---|---:|---|
| [`src/main.rs`](src/main.rs) | 51 | Binary entry point, `mimalloc::MiMalloc` allocator, env var parsing, Unix `_exit(0)` fast teardown. |
| [`src/csv.rs`](src/csv.rs) | 3,652 | `CsvSource` (`mmap` zero-copy + `pread` fallback), `scan_lines_direct_batched_avx2` (`DirectLineRef`), `CompactKey64`, `Hex128`, SSE4.1 `encode_b37_pair_padded` + `biject42`, AVX2 `encode_hex32_padded`, `LongArena`, `cmp_raw_keys`. |
| [`src/parse.rs`](src/parse.rs) | 1,696 | `DateCache` (64-entry pre-populated calendar cache), SWAR `parse_hms_sec_u64`, `parse_f1_pair_rel_sec_padded`, `parse_f2_pair_rel_sec_padded`, SSSE3 `parse_f3_only_13_padded`, `parse_price_cents`, `Manifest`. |
| [`src/links.rs`](src/links.rs) | 1,719 | `build_link_map`, lock-free DSU (`atomic_find`), `LinkGroup64` (64-byte cache-line 6-lane AVX2 probe group), `LinkSlotHex`, Bloom prefilters in `HugeBuf`, `LinkMap` (`probe_b37_at`, `probe_hex`, `resolve_comp_bytes`). |
| [`src/slab.rs`](src/slab.rs) | 598 | `SlabArena` (4 MiB mmap virtual slabs), `SlabBuckets` (sharded lock-free append buckets), `HugeBuf` (2 MiB-aligned anonymous `mmap` + `MADV_HUGEPAGE`). |
| [`src/parquet_out.rs`](src/parquet_out.rs) | 1,039 | Native Apache Parquet writer (`ThriftBuf`, `UserDailyWriter`, `write_campaign_daily`, `clean_parquet_dir`) outputting compliant uncompressed PLAIN/RLE Parquet files without Arrow overhead. |
| [`src/pipeline.rs`](src/pipeline.rs) | 9,010 | Full concurrent pipeline (`run_pipeline_with_exit`, `load_lookups`, `run_parse_clicks_and_dedup`, `EvLinkPipe`, `ClLinkPipe`, `run_stage5`, `avx2_sort`, `CampDailyAcc`, `PROFILE_DETAIL` / `PROFILE_MICRO`). |

---

## 4. Generalizing to Any Data-Intensive Problem (The Rosetta Stone)

Strip away the e-commerce column names, and `shopping-sessions` solves a **universal 5-table relational/temporal ETL pattern**:

| Engine Primitive | E-Commerce Baseline | Generic Data Engineering Meaning | Materials / DFT / MLIP Simulation Meaning |
|---|---|---|---|
| `links/*.csv` (`a,b`) | Alias graph linking cookies/devices | **Transitive Equivalence Graph**: merges duplicate keys/accounts/records into one canonical entity ID | **Structure / Polymorph / Restart Equivalence**: maps symmetrically equivalent structures, supercell re-indexings, MD restart chains, or `MP`↔`OQMD`↔`GNoME`↔MLIP IDs to one canonical material/site ID |
| `events/*.csv` (`event_id, user_id, ts, ingest_ts, event_type, product_id, price_cents`) | User telemetry (views, carts, purchases) | **Primary Fact Stream (with Idempotency + Validity Filter)**: deduplicated by priority key *before* validation, tagged by type/dimension, carrying an integer metric | **Simulation Evaluation Log**: DFT SCF/relaxation/NEB/AIMD jobs or MLIP inference/MD frames (`eval_id`, canonical or raw `structure_id`, `sim_time`/`step`/`V_app`, `priority_or_timestamp`, `fidelity_or_status`, `phase_or_adsorbate`, `scaled_energy_or_metric`) |
| `clicks/*.csv` (`click_id, user_id, campaign_id, ts`) | Ad touches (deduped by ID, joined backward) | **Secondary Context / Trigger Stream**: sparse events deduplicated by ID and joined backward onto primary episodes within `[t - W, t]` | **Validation / Regime / Active-Learning Anchors**: DFT checkpoint labels, active-learning retraining triggers, functional switches, temperature/voltage ramps, or experimental anchors in `[t - W, t]` |
| `products.csv` (`product_id, category`) | Catalog → Category map | **Static Dimension Lookup #1**: ultra-fast array/hash map classifying primary targets (`argmax` sum reported in summary) | **Chemistry / Adsorbate / Defect Lookup**: maps `adsorbate_id`/`composition_id`/`dopant_id` → dominant chemical family, intermediate (`*CO`, `*OOH`), defect type (`V_O`, `Li_i`), or reaction channel |
| `campaigns.csv` (`campaign_id, channel`) | Campaign → Channel map | **Static Dimension Lookup #2**: classifies context triggers into coarse summary groups | **Model / Functional / Workflow Lookup**: maps `model_checkpoint_id` or `workflow_id` (e.g., `MACE-MP0`, `HSE06-VASP`, `NEB-PBE`) → model family (`MLIP`, `hybrid-DFT`, `meta-GGA`, `experiment`) |
| `user_daily/*.parquet` & `campaign_daily/*.parquet` | Daily per-user KPIs & per-campaign credit/assists | **Entity-Windowed Fact Summary** + **Context Attribution Rollup** | **Per-Material / Per-Trajectory Summary** (states, converged steps, total/mean/min scaled energy, dominant species/defect) + **Per-MLIP-Checkpoint / Functional Performance & Active-Learning Assist Table** |

---

## 5. Computational Materials Science, DFT & MLIP Workflows

### 5.1 Why Computational Materials Pipelines Hit the Exact Same Bottlenecks

Modern high-throughput screening and universal MLIP training workflows generate **dirty, redundant, multi-source tabular logs at scales where Python/ASE/pymatgen/MongoDB choke**:

1. **Failed & Restarted HPC Jobs (`dedup-before-validation` is critical)**:
   Slurm/PBS timeouts leave partial `OUTCAR` / `vasprun.xml` / `pw.out` runs alongside resubmitted runs sharing a logical calculation/trajectory ID (`event_id`). Crucially, if the *canonical* highest-fidelity or latest converged run vs earliest run defines ground truth, you must **deduplicate on calculation/frame ID *before* dropping unconverged/NaN records**—otherwise stale or partial sibling records leak into ground-truth statistics.
2. **Polymorph, Symmetry, & Cross-Database Identity Explosion (`links` DSU)**:
   A single physical catalyst surface site, battery cathode host, or semiconductor defect appears under multiple IDs: a Materials Project ID (`mp-149`), an OQMD ID (`oqmd-4182`), a structure-matcher SHA hash (`u` + 32-hex), 50–400 chained MD continuation job IDs (`job_0001 -> job_0002 -> ... -> job_0400`), or two slightly perturbed relaxations proved isomorphic by `pymatgen.StructureMatcher` or SPGLIB. Lock-free DSU in [`src/links.rs`](src/links.rs) resolves **millions of equivalence edges and 400+ hop chains in ~0.1 seconds**, completely overlapped with parsing.
3. **Multi-Scale Multi-Fidelity Attribution (`events` + `clicks`)**:
   In active learning (MACE / CHGNet / NequIP / DeePMD fine-tuning) and hierarchical screening (`MLIP -> PBE -> r2SCAN -> HSE06 -> GW`), you constantly ask:
   - *Direct attribution (`credit`)*: For every converged DFT state or rare ion-hop episode, **which prior MLIP model checkpoint, committee uncertainty spike, or active-learning batch triggered/predicted it** within lookback window Δt?
   - *Assist attribution (`assists`)*: Across all models in an active-learning ensemble or DFT pre-relaxation cascade, **which surrogate checkpoints participated within the lookback horizon** of a discovered low-energy polymorph or transition state?

### 5.2 Recommended Two-Tier Architecture (Extract → Rust Engine → Python/DuckDB Analysis)

Rather than loading 20M–200M `ase.Atoms` objects or `pymatgen.ComputedEntry` JSONs into one Python process:

```text
Tier 1: Embarrassingly Parallel HPC Extractors (SLURM array / Rust / lightweight ASE readers)
  ├── Parse raw OUTCAR / vasprun.xml / extxyz / MACE trajectories per directory
  ├── Compute composition / spacegroup / SHA-256 fingerprint (u<32-hex>)
  ├── Emit sharded CSVs to NVMe /scratch: events/*.csv, clicks/*.csv, links/*.csv
  └── Keep per-job extractors stateless and tiny

Tier 2: This Engine (`shopping-sessions` / extended binary, 8-64 cores, single node)
  ├── Zero-copy mmap CSV ingestion + UTF-8/NaN/malformed sanitation
  ├── Transitive DSU canonicalization over polymorph/restart/cross-DB links
  ├── Exact dedup-before-validation + per-material AVX2 sort + episode grouping
  └── Direct uncompressed Parquet output -> user_daily/*.parquet & campaign_daily/*.parquet

Tier 3: Interactive Science (Polars / DuckDB / PyArrow / Jupyter, <1s queries)
  └── Construct convex hulls, Pourbaix diagrams, Arrhenius plots, volcano curves, parity plots
```

### 5.3 Catalysis & Electrocatalysis Workflows

*(ORR/OER, HER, CO₂RR, N₂RR, NH₃ synthesis, thermocatalysis across alloy slabs, SACs, zeolites, oxides)*

- **`links/*.csv` (Site & Adsorbate Equivalence)**:
  Map symmetry-equivalent adsorption sites (e.g., `(111)-fcc-site0` ↔ `(111)-fcc-site3`), MLIP pre-relaxation job IDs ↔ final DFT `CONTCAR` fingerprints, or slab thickness variants into one canonical `(slab, site, adsorbate)` key.
- **`products.csv` (Adsorbate / Reaction Intermediate Taxonomy)**:
  Map `product_id` (e.g., `ads_CO_top`, `ads_OOH_bridge`, `TS_CO_O`) → intermediate family (`*CO`, `*CHO`, `*O`, `*OH`, `*OOH`, `TS_C_C`).
- **`events/*.csv` (Relaxations, Single-Points & CI-NEB Evaluations)**:
  - `event_type`: map `view` / `cart` / `purchase` (or domain variants) to `mlip_relax` (screening), `dft_opt` (converged intermediate), and `dft_ts` / `neb_converged` (scored reaction barrier / free energy).
  - Scaled magnitude (`price_cents` → `e_ads_shifted_mev` or `barrier_mev`): integer fixed-point adsorption energy relative to a reference offset (`eV × 1000 + BIAS`), enabling volcano distance or Boltzmann weights.
- **`clicks/*.csv` & `campaigns.csv` (Surrogate Models, Functionals & Potential Steps)**:
  Record active-learning checkpoints (`mace_v3_ft`, `equiformer_oc20`), DFT functionals (`rpbe_d3`, `beef_vdw`), or applied potential triggers (`U_0p8V_RHE`).
- **Resulting Summary Power**:
  - `user_daily`-style table summarizes every canonical `(catalyst_surface, active_site)` across screening phases: number of evaluated intermediate episodes, total converged runs, min/cumulative adsorption energy, and `top_category` = **rate-determining or strongest-binding intermediate** (`*OOH` vs `*CO`).
  - `campaign_daily`-style table measures **how many DFT-validated low-overpotential hits each MLIP checkpoint or functional discovered (`sessions`), produced valid barriers for (`purchasing_sessions`), and co-assisted (`assisted_sessions`)**.

### 5.4 Solar / Photovoltaics & Optoelectronics

*(Halide perovskites, chalcogenides, kesterites, tandem absorbers, transparent conducting oxides)*

- **`links/*.csv` (Cross-Database & Polymorph Deduplication)**:
  Join structure hashes generated by GNoME / MatterGen / CDVAE / elemental substitution with Materials Project (`mp-*`), ICSD, OQMD, and AFLOW entries via transitive DSU—never waste HSE06/GW compute twice on equivalent tilted octahedra (`Pm-3m` vs relaxed supercell).
- **`products.csv` (Structural Prototype / Dimensionality Taxonomy)**:
  Map composition/prototype keys → `3D_perovskite`, `2D_ruddlesden_popper`, `chalcopyrite`, `spinel`, `double_perovskite`.
- **`events/*.csv` (Multi-Fidelity Band Gap, Stability & Optical Funnel)**:
  Track `MLIP_hull_screen`, `PBE_opt`, and `HSE06_band_gap` (or `GW_SLME`) records across candidate IDs; scale `E_g` (meV) or SLME (%) into integer fixed-point metrics; use the 24-hour staleness check (adapted to structural drift `RMSD > threshold` or `f_max > 0.05 eV/Å`) to discard blown-up relaxations cleanly after deduplication.
- **`clicks/*.csv` & `campaigns.csv` (Generative / Surrogate Attribution)**:
  Attribute every experimentally viable candidate (`1.1 eV <= E_g <= 1.6 eV` and `E_hull <= 30 meV/atom`) back to the generative model or active-learning round (`diffcsp_r4`, `chgnet_prescreen`, `hse06_batch7`) that nominated it.

### 5.5 Batteries & Solid-State Electrolytes

*(Cathode intercalation Ni-rich NMC/LFP/LNMO, garnet/argyrodite/halide Li⁺/Na⁺ solid electrolytes, SEI MD)*

Here the **sessionization (`MS_SESSION_GAP`) and 400+ hop DSU chains** shine naturally:

- **`links/*.csv` (Trajectory Continuation Chains & Equivalent Hop Sites)**:
  MLIP-MD runs on supercells (Li₆PS₅Cl, LLZO, NMC811) routinely span hundreds of SLURM restart segments (`seg_0001 -> seg_0002 -> ... -> seg_0350`) or symmetry-equivalent 48h/24c crystallographic Li cages. The lock-free DSU in [`src/links.rs`](src/links.rs) resolves 400-node chains in linear work with path halving.
- **Sessionization (`ts` + `MS_SESSION_GAP`) → Correlated Ion-Hop Bursts & Voltage Plateaus**:
  Map `ts` from wall-clock time to **MD simulation time (ps or fs mapped monotonically)** or **state-of-charge / composition grid**:
  - **Solid-state ion transport**: Feed Li⁺/Na⁺ hop events (`Δr > r_cut`) into `events/*.csv`. Consecutive hops within `Δt <= tau_corr` (e.g., `5 ps`) automatically group into a single **correlated string-like/concerted diffusion episode ("session")**, while gaps `> tau_corr` start a new diffusion episode!
  - **Voltage / Deintercalation sweeps**: Map monotonic Li concentration `x` or MD temperature ramp `T` to `ts`; distinct structural phase plateaus split into cleanly aggregated episodes (`day` = temperature bin or voltage step).
- **`products.csv` & `top_category`**:
  Map hop path ID or voltage phase ID → migration channel (`16d_to_16d`, `cage_to_cage`, `intra_plane`, `inter_plane`). `top_category` immediately identifies the **dominant transport mechanism or dominant degradation species** at each temperature bin without a single SQL `GROUP BY`.
- **`clicks/*.csv` → Temperature Steps & Active-Learning Force-Error Triggers**:
  Every time MLIP ensemble force variance σ_F spikes (`clicks/*.csv`) or the thermostat steps from `300K -> 450K -> 600K`, `clicks` within the lookback horizon attribute subsequent ion-hop or SEI reaction bursts to the active-learning query or thermal regime that preceded them.

### 5.6 Semiconductors, Point Defects & Electronic Devices

*(GaN, SiC, Ga₂O₃, diamond, CdTe, halide & oxide defects, carrier transport, interfaces)*

- **`links/*.csv` (Defect Complex & Charge-State Grouping)**:
  Tie symmetry-equivalent atomic Wyckoff configurations, neutral/charged supercells (`V_Ga^0`, `V_Ga^-1`, `V_Ga^-2`, `V_Ga^-3`), and finite-size electrostatic correction runs (`FNV`/`Kumagai`) under one canonical defect family ID.
- **`products.csv` (Defect / Sublattice Class)**:
  Map site IDs → defect motifs (`cation_vacancy`, `anion_vacancy`, `antisite`, `interstitial`, `DX_center`).
- **`events/*.csv` + Stage 5 Segmentation**:
  Group calculations ordered by **Fermi level `E_F` grid** (mapped monotonically onto `ts`, with phase transitions / band-edge regimes as `day` bins) or relaxation iteration trajectory; compute cumulative/minimum formation energies `E^f(D^q, E_F)`, track converged charged defects, and report **`top_category` = dominant compensating defect** across Fermi-level / chemical-potential regimes (Cu-rich vs Cu-poor, N-rich vs Ga-rich).
- **`clicks/*.csv` & `campaigns.csv`**:
  Compare functionals (`HSE06_a0.25`, `HSE06_a0.32`, `PBE+U`, `MLIP_charge_equivariant`) on exact parity, pinning behavior, and active-learning assist rate in `campaign_daily`.

---

## 6. Developer Playbook: Extending the Rust Engine to Your Scientific Schema

Because this repository is clean, modular Rust without generated frameworks, adapting it to a custom computational materials pipeline requires touching only targeted functions while preserving **90%+ of the high-speed CSV, DSU, slab, hash-group, sort, and Parquet infrastructure verbatim**.

### Step A — Encode Domain Quantities in Fixed-Point Integers (`pipeline.rs`, `parse.rs`)

Floating-point reductions across multi-threaded dynamic partitions are non-associative (order-dependent rounding drift). For reproducible scientific reductions and compact `16`-byte structs (`PersonEvent16`), represent physical quantities in scaled `i32`/`i64` fixed-point units:

| Physical Quantity | Recommended Fixed-Point Scale | Range in 24–32 bits | Code Location |
|---|---|---|---|
| Formation / adsorption energy (`ΔE`) | `meV` or `0.1 meV` (`× 10_000` + bias) | `±214,000 eV` (32-bit signed) | [`src/parse.rs`](src/parse.rs) (`parse_price_cents` → `parse_signed_scaled`) |
| Energy above hull (`E_hull`) / Band gap (`E_g`) | `meV/atom` or `meV` (`0 .. 20_000 meV`) | Exact 24 bits (`<= 16.7M`) | [`src/pipeline.rs`](src/pipeline.rs) (`PersonEvent16::price_cat`) |
| Max atomic force (`f_max`) / Stress | `0.1 meV/Å` | Positive threshold check (`<= 500` for `0.05 eV/Å`) | [`src/pipeline.rs`](src/pipeline.rs) (late-event / convergence filter) |
| MD time / `E_F` / Voltage / Temp grid | Monotonic `i64` integer ticks (`fs`, `ps`, `mV`, `K`) | Full 64-bit (`PersonEventWide`) or relative `u32` ms (`PersonEvent16`) | [`src/parse.rs`](src/parse.rs) & [`src/pipeline.rs`](src/pipeline.rs) |

> **Zero-loss wide mode already exists**: If timestamps or simulation coordinates exceed 31-bit relative bounds or `categories.len() > 256`, `run_pipeline_inner` in [`src/pipeline.rs`](src/pipeline.rs) automatically dispatches `PersonEventWide` (`32` bytes, `i64 ts_ms`, `u32 price_cents`, `u32 cat_id`) and `PersonClickWide` without changing any downstream logic!

### Step B — Leverage `CompactKey64` & `Hex128` for Structure Hashes & Material IDs (`csv.rs`)

[`src/csv.rs`](src/csv.rs) gives specialized SIMD codecs zero-allocation speed for common scientific ID patterns:

1. **Hex Structure Fingerprints (`u<32-hex>` / `k<32-hex>`)**: Prefix a 128-bit crystal/graph hash (e.g., first 32 lowercase hex chars of SHA-256 of canonical Wyckoff/PyMatGen `Structure` string) with `u` (material/site) or `k` (job/anchor). `encode_hex32_padded` decodes 32 hex bytes into `Hex128` (`16` bytes) in **one AVX2 pass**.
2. **Short Alphanumeric Material IDs (`u[0-9a-z]{1,8}`, `k[0-9a-z]{1,8}`)**: Encoded via SSE4.1 `encode_b37_pair_padded` + `biject42` into 42 inline bits with 6-bit shard routing.
3. **Arbitrary Strings (`mp-149`, `Li7La3Zr2O12_c1`, `NMC811_site42`)**: Inline `1..=9` ASCII bytes pack losslessly via `_pext_u64`/`_pdep_u64` inside `CompactKey64`; anything longer falls back cleanly into per-worker `LongArena` bump buffers. *(Note: update `encode_raw_inline_padded` or `parse_canonical_uint_padded` if customizing prefix acceleration in `lookups` (`p` / `c_`), see [`src/pipeline.rs`](src/pipeline.rs) `load_lookups`.)*

### Step C — Customize Canonical Selection in Disjoint Set Union (`links.rs`)

Currently [`src/links.rs`](src/links.rs) (`run_dsu_edges`) picks the byte-wise smallest string (`cmp_raw_keys`) as the canonical component root, so lexicographic prefixes control priority automatically without touching Rust code:
- **Zero-code convention**: Prefix experimental/trusted ICSD or MP canonical entries with `0_` or `!` (e.g., `!icsd_12345` < `mp-149` < `u<mlip_hash>`), and `cmp_raw_keys` will deterministically name the component after the highest-authority ID!
- **Custom Rust comparator**: Edit `cmp_raw_keys` in [`src/links.rs`](src/links.rs) to parse fidelity tiers or spacegroup numbers directly.

### Step D — Implement Fidelity-Aware Dedup Before Validation (`pipeline.rs`)

In [`src/pipeline.rs`](src/pipeline.rs) (`dedup_p1` around `P_DEDUP` / `P_HEX_DEDUP`), duplicates of an `event_id` currently keep the copy with minimum `ev16_ingest_ts(...)`:

```rust
// Replace timestamp comparison in P_DEDUP & P_HEX_DEDUP with fidelity + timestamp tie-break:
//   keep copy maximizing: (fidelity_rank, converged_flag, -ingest_ts)
// Example: HSE06 (rank 4) beats PBE (rank 3) beats MACE (rank 1); equal fidelity keeps earliest/latest clean run.
```

Because `process_ev_line_any` emits `PE_INV_B37` / `HX_TS_INVALID` / `PE_EXT_GEN` placeholders even for failed/unconverged rows, **an unconverged higher-fidelity DFT run will still flag and mask stale MLIP placeholders** until validation/filtering removes invalid winners in Pass 2!

### Step E — Swap Temporal Gaps for Reaction Coordinates, Voltage Windows, or Hop Bursts (`pipeline.rs`)

Stage 5 (`run_stage5` in [`src/pipeline.rs`](src/pipeline.rs)) assumes only **monotonic sorting on `ts_rel_ms` / `ts_ms`** and a gap check `E::gap_exceeds(e_ts, prev_ts)`:
1. Change `MS_SESSION_GAP` in [`src/parse.rs`](src/parse.rs) (`1_800_000` ms) to your domain episode threshold (e.g., `5_000` for 5 ps ion-hop correlation, `50` for 50 mV potential plateau, or `1` to treat every discrete calculation step as a separate episode).
2. Adapt the per-episode accumulator inside `run_stage5` (`sess_rev`, `day_rev`, `cat_rev`, `pick_and_reset_top_cat_id`) from `sum` to `min`, `max`, `sum(f_max²)`, or Boltzmann log-sum-exp over `price_cents`!
3. Change `MS_CLICK_REACH` (`7` days = `604_800_000` ms) in [`src/parse.rs`](src/parse.rs) to control how far back active-learning checkpoints or reference triggers (`clicks/*.csv`) can credit/assist an episode.

### Step F — Add Scientific Parquet Columns Without Heavy Dependencies (`parquet_out.rs`)

[`src/parquet_out.rs`](src/parquet_out.rs) implements Parquet schema + `TCompactProtocol` serialization directly (~15 lines per column):
- Primitive Thrift types supported directly by `write_schema_elem`: `PQ_TYPE_INT32 = 1`, `PQ_TYPE_INT64 = 2`, `PQ_TYPE_DOUBLE = 5` (standard Parquet `Type::DOUBLE`), `PQ_TYPE_BYTE_ARRAY = 6` (`PQ_CT_UTF8 = 0`).
- To add a new `f64` column (e.g. `min_energy_ev` or `diffusion_d_cm2_s`): add a `Vec<f64>` field to `UserDailyWriter` / `CampaignRow`, increase `RowGroupMeta::cols` array size (`6 -> 7`) and child count in `write_schema_elem`, write little-endian `[f64]` byte slices via `from_raw_parts`, and emit the column chunk metadata inside `flush_row_group` / `close`. Verify roundtrip types cleanly using `cargo test` (`parquet` dev-dependency reads back every column!).

---

## 7. End-to-End Worked Example: Active-Learning Catalysis & Battery Screening

Below is a concrete zero-code-change mapping showing how you can run the **unmodified binary today** (encoding energy margins / scaled metrics in `price_cents` and monotonic simulation time/trajectory steps in `ts`) to audit a 20M-frame catalysis or solid-electrolyte screening campaign, then query the Parquet output in DuckDB or Polars.

### Sample Input Files

**`manifest.json`** (window spans synthetic time axis mapping MD `ps` or campaign wall dates):
```json
{"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-02-01T00:00:00Z"}
```

**`links/equiv.csv`** (merges Materials Project IDs, symmetry-equivalent active sites, and MD continuation job hashes):
```csv
user_id_a,user_id_b
mp-2815_fcc0,!CuPt_111_fcc
mlip_hash_9f8a,!CuPt_111_fcc
llzo_seg001,llzo_seg002
llzo_seg002,!LLZO_cubic_48h
```

**`products.csv`** (maps target intermediates / hop channels → physical family):
```csv
product_id,category
ads_CO_01,star_CO
ads_OOH_02,star_OOH
hop_16d_cage,concerted_string
```

**`campaigns.csv`** (maps MLIP checkpoints & DFT functionals → method class):
```csv
campaign_id,channel
c_mace_ft3,mlip_active_learn
c_chgnet_v0,mlip_foundation
c_vasp_rpbe,dft_gga
```

**`events/part-000.csv`** (screening + converged DFT runs; scaled stability score / barrier margin stored in integer `price_cents`):
```csv
event_id,user_id,ts,ingest_ts,event_type,product_id,price_cents
e001,mp-2815_fcc0,2026-01-10T01:00:00Z,2026-01-10T01:05:00Z,view,ads_CO_01,
e001,mp-2815_fcc0,2026-01-10T01:00:00Z,2026-01-10T01:02:00Z,purchase,ads_CO_01,620
e002,mlip_hash_9f8a,2026-01-10T01:12:00Z,2026-01-10T01:13:00Z,purchase,ads_OOH_02,1480
e003,llzo_seg002,2026-01-12T00:00:01Z,2026-01-12T00:00:02Z,purchase,hop_16d_cage,310
```
*(Notice duplicate `e001` cleanly keeps the `01:02:00Z` converged `purchase` record (`620`) over the later retry at `01:05:00Z`, and `!CuPt_111_fcc` aggregates both `mp-2815_fcc0` and `mlip_hash_9f8a` under one canonical surface site!)*

**`clicks/triggers.csv`** (which MLIP checkpoint / functional proposed or retrained on that material prior to validation):
```csv
click_id,user_id,campaign_id,ts
k01,mlip_hash_9f8a,c_chgnet_v0,2026-01-08T12:00:00Z
k02,!CuPt_111_fcc,c_mace_ft3,2026-01-10T00:30:00Z
k03,llzo_seg001,c_mace_ft3,2026-01-11T23:55:00Z
```

Run the engine:
```bash
DATA_DIR=/scratch/mat_run OUTPUT_DIR=/scratch/mat_out PROFILE=1 ./target/release/shopping-sessions
```

### Downstream DuckDB / Polars Queries on Parquet Outputs

```python
import duckdb

con = duckdb.connect()

# 1. Canonical Material / Active-Site Screening Summary (resolved across all polymorphs & restarts)
print(con.execute("""
    SELECT
        user_id              AS canonical_material_or_site,
        day                  AS regime_bin,
        sessions             AS distinct_episodes,
        events               AS converged_evals,
        revenue_cents / 1000.0 AS cumulative_score_or_eV,
        top_category         AS dominant_intermediate_or_channel
    FROM read_parquet('/scratch/mat_out/user_daily/*.parquet')
    ORDER BY cumulative_score_or_eV DESC
    LIMIT 20
""").fetchdf())

# 2. MLIP Checkpoint & Functional Screening Efficiency + Active-Learning Assist Audit
print(con.execute("""
    SELECT
        campaign_id,
        channel                          AS method_family,
        SUM(sessions)                    AS total_episodes_attributed,
        SUM(purchasing_sessions)         AS dft_validated_hits,
        ROUND(100.0 * SUM(purchasing_sessions) / NULLIF(SUM(sessions), 0), 2) AS hit_rate_pct,
        SUM(revenue_cents) / 1000.0      AS total_discovered_score,
        SUM(assisted_sessions)           AS ensemble_assists
    FROM read_parquet('/scratch/mat_out/campaign_daily/*.parquet')
    GROUP BY campaign_id, channel
    ORDER BY dft_validated_hits DESC
""").fetchdf())
```

---

## 8. Systems & HPC Performance Notes

- **Memory Sizing & 2 MiB HugePages (`src/slab.rs`)**:
  `HugeBuf::new_zeroed` automatically uses 2 MiB-aligned anonymous `mmap` + `MADV_HUGEPAGE` for buffers `>= 512 KiB`, keeping TLB misses low on dense Xeon nodes. All shard append buffers (`PE_CHUNK_LEN = 2048`, `CL_CHUNK_LEN = 512`, `EV_CHUNK_LEN = 1024`) live in 4 MiB virtual slabs (`SlabArena`) and bypass destructor scans on exit via `_exit(0)` (`fast_exit = true`).
- **NVMe `/scratch` vs Distributed Filesystems (Lustre / GPFS / NFS)**:
  [`CsvSource`](src/csv.rs) currently uses read-only `mmap` (`MAP_PRIVATE` + `MADV_SEQUENTIAL`), which gives near-zero syscall overhead on local NVMe SSDs and warm Linux page caches, at the cost of kernel page-table teardown in `_exit(0)` and virtual RSS tracking the size of mapped input CSVs. On Lustre/GPFS where `mmap` lock contention or quota RSS limits matter, disable the Unix `mmap` branch in `CsvSource::open` (`src/csv.rs`) to automatically engage the built-in `pread` + `posix_fadvise(POSIX_FADV_SEQUENTIAL)` streaming path.
- **Compiler Flags (`x86-64-v3` + `pclmulqdq`)**:
  Compile with `RUSTFLAGS="-C target-cpu=x86-64-v3 -C target-feature=+pclmulqdq"`. Note AVX-512 instructions are *not* emitted, ensuring identical binary compatibility across Intel Cascade Lake/Sapphire Rapids (`n2`), Alder Lake/Raptor Lake laptops, and AMD Zen3/Zen4 EPYC compute nodes.

---

## 9. Troubleshooting & Verification

- **Row/metric diffing**: Compare two output folders (or CSV ground-truth vs Parquet) with:
  ```bash
  python3 scripts/compare.py /path/to/expected /path/to/actual
  ```
- **Fixture regression harness**:
  ```bash
  python3 scripts/run_fixtures.py fixtures -- ./target/release/shopping-sessions
  ```
- **Common CSV pitfalls**:
  - Windows CRLF line endings (`\r\n`): `\r` stays attached to the last column (`1000\r` fails `parse_price_cents`, `...Z\r` fails F1 timestamp parsing). Strip `\r` when exporting from Windows/Excel scripts.
  - Non-ASCII digits (`２５０`), `NaN`, or `Inf`: strictly rejected by `parse_price_cents` and F3 timestamp validators.
  - Quoted empty fields (`""`): parsed cleanly as null/empty.
  - Unset `NCPU` inside shared Slurm allocations: explicitly set `NCPU=$SLURM_CPUS_PER_TASK` so the binary does not spawn threads for unallocated host cores when cgroup cpusets aren't enforced.

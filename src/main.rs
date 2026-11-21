mod csv;
mod links;
mod parse;
mod parquet_out;
mod pipeline;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    let data_dir = PathBuf::from(env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string()));
    let out_dir = PathBuf::from(env::var("OUTPUT_DIR").unwrap_or_else(|_| "/output".to_string()));
    let default_cpus = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1);
    let ncpu = env::var("NCPU")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(default_cpus);
    let profile = env::var("PROFILE").ok().as_deref() == Some("1");

    let pool = match rayon::ThreadPoolBuilder::new().num_threads(ncpu).build() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to initialize rayon pool: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = pool.install(|| pipeline::run_pipeline(&data_dir, &out_dir, ncpu, profile));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pipeline error: {e}");
            ExitCode::FAILURE
        }
    }
}

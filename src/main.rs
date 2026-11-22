mod csv;
mod links;
mod parquet_out;
mod parse;
mod pipeline;
mod slab;

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(unix)]
extern "C" {
    fn _exit(status: i32) -> !;
}

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

    let result = pipeline::run_pipeline_with_exit(&data_dir, &out_dir, ncpu, profile, true);
    match result {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::io::Write;
                let _ = std::io::stdout().flush();
                let _ = std::io::stderr().flush();
                unsafe { _exit(0) };
            }
            #[cfg(not(unix))]
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pipeline error: {e}");
            ExitCode::FAILURE
        }
    }
}

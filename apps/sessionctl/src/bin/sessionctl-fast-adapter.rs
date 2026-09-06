#![forbid(unsafe_code)]

use std::{ffi::OsString, path::PathBuf};

use sessionctl::FastAdapterPathMode;

#[tokio::main]
async fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [command, mode, authority] if command == "host" => {
            let Some(mode) = mode.to_str() else {
                unsupported();
            };
            let mode = mode.parse::<FastAdapterPathMode>();
            match mode {
                Ok(mode) => sessionctl::run_fast_adapter_host(mode, PathBuf::from(authority)).await,
                Err(error) => Err(error),
            }
        }
        [command, mode, authority] if command == "join" => {
            let Some(mode) = mode.to_str() else {
                unsupported();
            };
            let mode = mode.parse::<FastAdapterPathMode>();
            match mode {
                Ok(mode) => sessionctl::run_fast_adapter_join(mode, PathBuf::from(authority))
                    .await
                    .map(|_| ()),
                Err(error) => Err(error),
            }
        }
        _ => unsupported(),
    };
    if result.is_err() {
        eprintln!("sessionctl-fast-adapter: Fast adapter evidence run failed");
        std::process::exit(1);
    }
}

fn unsupported() -> ! {
    eprintln!(
        "usage: sessionctl-fast-adapter host <auto|relay-only> <absolute-new-authority-file> | join <auto|relay-only> <absolute-authority-file>"
    );
    std::process::exit(2);
}

#![forbid(unsafe_code)]

use std::{ffi::OsString, path::PathBuf};

#[tokio::main]
async fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [mode, root] if mode == "host" => sessionctl::run_network_host(PathBuf::from(root)).await,
        [mode, host, root] if mode == "join" => {
            let Some(host) = host.to_str() else {
                unsupported();
            };
            sessionctl::run_network_join(host, PathBuf::from(root)).await
        }
        _ => unsupported(),
    };
    if result.is_err() {
        eprintln!("sessionctl-net: Fast network proof failed");
        std::process::exit(1);
    }
}

fn unsupported() -> ! {
    eprintln!(
        "usage: sessionctl-net host <absolute-new-state-dir> | join <host-endpoint-id> <absolute-new-state-dir>"
    );
    std::process::exit(2);
}

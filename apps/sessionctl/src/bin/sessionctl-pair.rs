#![forbid(unsafe_code)]

use std::{ffi::OsString, path::PathBuf};

fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [mode, root] if mode == "host" => sessionctl::run_two_terminal_host(PathBuf::from(root)),
        [mode, root] if mode == "join" => sessionctl::run_two_terminal_join(PathBuf::from(root)),
        _ => unsupported(),
    };
    if result.is_err() {
        eprintln!("sessionctl-pair: two-terminal proof failed");
        std::process::exit(1);
    }
}

fn unsupported() -> ! {
    eprintln!("usage: sessionctl-pair <host|join> <absolute-new-run-directory>");
    std::process::exit(2);
}

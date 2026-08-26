#![forbid(unsafe_code)]

use std::{ffi::OsString, path::PathBuf};

fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = match arguments.as_slice() {
        [] => sessionctl::run_l1_process_demo().map(|report| print!("{}", report.encode_v1())),
        [mode, role, root] if mode == "--internal-role" => {
            let Some(role) = role.to_str() else {
                unsupported();
            };
            sessionctl::run_l1_process_internal_role(role, PathBuf::from(root))
        }
        _ => unsupported(),
    };
    if result.is_err() {
        eprintln!("sessionctl-l1: independent-process conformance flow failed");
        std::process::exit(1);
    }
}

fn unsupported() -> ! {
    eprintln!("sessionctl-l1: unsupported invocation");
    std::process::exit(2);
}

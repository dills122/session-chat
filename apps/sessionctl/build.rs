use std::{
    env,
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=PATH");

    let cargo_rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let cargo_rustc = resolve_executable(&cargo_rustc).expect("Cargo rustc must be resolvable");
    let sysroot_output = Command::new(&cargo_rustc)
        .args(["--print", "sysroot"])
        .output()
        .expect("Cargo rustc must report its sysroot");
    assert!(
        sysroot_output.status.success(),
        "Cargo rustc sysroot failed"
    );
    assert!(
        sysroot_output.stderr.is_empty(),
        "Cargo rustc sysroot wrote stderr"
    );
    let sysroot = one_line(&sysroot_output.stdout, "Cargo rustc sysroot");
    let sysroot = PathBuf::from(sysroot);
    assert!(
        sysroot.is_absolute(),
        "Cargo rustc sysroot must be absolute"
    );
    let trusted_rustc = sysroot
        .join("bin")
        .join(format!("rustc{}", env::consts::EXE_SUFFIX))
        .canonicalize()
        .expect("toolchain rustc must exist in Cargo rustc sysroot");

    let verbose = Command::new(&trusted_rustc)
        .arg("-Vv")
        .output()
        .expect("toolchain rustc must report verbose provenance");
    assert!(verbose.status.success(), "toolchain rustc -Vv failed");
    assert!(
        verbose.stderr.is_empty(),
        "toolchain rustc -Vv wrote stderr"
    );
    assert!(
        verbose.stdout.len() <= 4_096,
        "toolchain rustc -Vv exceeded bound"
    );
    let verbose = std::str::from_utf8(&verbose.stdout).expect("toolchain rustc -Vv must be UTF-8");
    let release = unique_field(verbose, "release");
    let commit = unique_field(verbose, "commit-hash");
    let host = unique_field(verbose, "host");
    assert!(
        is_version(release),
        "toolchain rustc release must be a version"
    );
    assert!(
        is_lower_hex(commit, 40),
        "toolchain rustc commit must be lowercase hex"
    );
    assert!(
        is_token(host, 128),
        "toolchain rustc host must be a bounded token"
    );

    let path = trusted_rustc
        .to_str()
        .expect("toolchain rustc path must be UTF-8");
    assert!(
        !path.contains('\r') && !path.contains('\n'),
        "toolchain rustc path must be one line"
    );
    println!("cargo:rerun-if-changed={path}");
    println!("cargo:rustc-env=SESSION_CHAT_BUILD_RUSTC_PATH={path}");
    println!(
        "cargo:rustc-env=SESSION_CHAT_BUILD_RUSTC_SHA256={}",
        file_sha256(&trusted_rustc)
    );
    println!("cargo:rustc-env=SESSION_CHAT_BUILD_RUSTC_RELEASE={release}");
    println!("cargo:rustc-env=SESSION_CHAT_BUILD_RUSTC_COMMIT={commit}");
    println!("cargo:rustc-env=SESSION_CHAT_BUILD_RUSTC_HOST={host}");
}

fn resolve_executable(executable: &OsStr) -> Option<PathBuf> {
    let path = Path::new(executable);
    if path.is_absolute() || path.components().count() > 1 {
        return path
            .is_file()
            .then(|| absolute_path(path))
            .and_then(Result::ok);
    }
    env::split_paths(&env::var_os("PATH")?).find_map(|directory| {
        let candidate = directory.join(path);
        if candidate.is_file() {
            return absolute_path(&candidate).ok();
        }
        #[cfg(windows)]
        {
            let candidate = directory.join(format!("{}.exe", path.to_string_lossy()));
            if candidate.is_file() {
                return absolute_path(&candidate).ok();
            }
        }
        None
    })
}

fn absolute_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn one_line<'a>(bytes: &'a [u8], label: &str) -> &'a str {
    let text = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("{label} must be UTF-8"));
    let value = text.trim_end_matches(['\r', '\n']);
    assert!(
        !value.is_empty() && !value.contains('\r') && !value.contains('\n'),
        "{label} must be one line"
    );
    value
}

fn unique_field<'a>(text: &'a str, name: &str) -> &'a str {
    let prefix = format!("{name}: ");
    let mut values = text.lines().filter_map(|line| line.strip_prefix(&prefix));
    let value = values
        .next()
        .unwrap_or_else(|| panic!("missing rustc {name}"));
    assert!(values.next().is_none(), "duplicate rustc {name}");
    value
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn is_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

fn file_sha256(path: &Path) -> String {
    let mut file = File::open(path).expect("toolchain rustc must be readable");
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("toolchain rustc read failed");
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let mut encoded = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

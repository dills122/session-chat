#![cfg(not(session_chat_storage_fault_testing))]

use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn ordinary_build_does_not_export_fault_testing() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    let fixture_root = std::env::temp_dir().join(format!(
        "session-chat-storage-fault-compile-fail-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(fixture_root.join("src")).expect("fixture directory");
    fs::write(
        fixture_root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"fault-module-unavailable\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\nstorage-sqlcipher = {{ path = {:?} }}\n\n[workspace]\n",
            manifest_dir
        ),
    )
    .expect("fixture manifest");
    fs::write(
        fixture_root.join("src/main.rs"),
        include_str!("compile_fail/fault_module_unavailable.rs"),
    )
    .expect("fixture source");

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .arg("check")
        .arg("--offline")
        .arg("--quiet")
        .current_dir(&fixture_root)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .expect("compile-fail cargo check");
    let stderr = String::from_utf8_lossy(&output.stderr);

    let cleanup = fs::remove_dir_all(&fixture_root);
    assert!(!output.status.success(), "fixture unexpectedly compiled");
    assert!(
        stderr.contains("fault_testing"),
        "fixture failed for an unrelated reason: {stderr}"
    );
    cleanup.expect("fixture cleanup");
}

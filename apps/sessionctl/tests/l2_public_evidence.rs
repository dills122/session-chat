#![forbid(unsafe_code)]

#[cfg(not(session_chat_storage_fault_testing))]
#[test]
fn ordinary_build_cannot_activate_public_l2_evidence() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sessionctl-l2"))
        .output()
        .expect("run ordinary L2 binary");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"sessionctl-l2: unavailable\n");
}

#[cfg(session_chat_storage_fault_testing)]
mod checked {
    use std::{
        fs,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn low_level_evidence_forgery_api_is_not_public() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(std::path::Path::parent)
            .expect("sessionctl belongs to the workspace");
        let target_dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    workspace_root.join(path)
                }
            })
            .unwrap_or_else(|| workspace_root.join("target"));
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let fixture_root = std::env::temp_dir().join(format!(
            "session-chat-l2-evidence-api-compile-fail-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(fixture_root.join("src")).expect("fixture directory");
        fs::write(
            fixture_root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"l2-evidence-forgery-api\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[dependencies]\nsessionctl = {{ path = {:?} }}\n\n[workspace]\n",
                manifest_dir
            ),
        )
        .expect("fixture manifest");
        fs::write(
            fixture_root.join("src/main.rs"),
            concat!(
                "use sessionctl::l2_process::{L2EvidenceMetadata, L2EvidenceSweep, ",
                "promote_l2_evidence};\n",
                "fn main() {}\n",
            ),
        )
        .expect("fixture source");

        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = Command::new(cargo)
            .args(["check", "--offline", "--quiet"])
            .current_dir(&fixture_root)
            .env("CARGO_TARGET_DIR", &target_dir)
            .output()
            .expect("compile-fail cargo check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let isolated_target_created = fixture_root.join("target").exists();
        let cleanup = fs::remove_dir_all(&fixture_root);

        assert!(
            !output.status.success(),
            "forgery API unexpectedly compiled"
        );
        assert!(
            stderr.contains("private") || stderr.contains("unresolved import"),
            "fixture failed for an unrelated reason: {stderr}",
        );
        assert!(
            !isolated_target_created,
            "compile-fail fixture must reuse the bounded workspace target directory",
        );
        cleanup.expect("fixture cleanup");
    }
}

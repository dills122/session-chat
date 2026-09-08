use std::path::Path;

use git2::{Repository, RepositoryState, StatusOptions};

#[cfg(session_chat_storage_fault_testing)]
use std::{ffi::OsStr, fs::File, io::Read};

#[cfg(session_chat_storage_fault_testing)]
use aws_lc_rs::digest::{Context, SHA256};

use super::{SessionCtlError, stage};

#[cfg(session_chat_storage_fault_testing)]
pub(crate) struct CompilerProvenance {
    pub(crate) release: String,
    pub(crate) commit: String,
    pub(crate) host: String,
    pub(crate) digest: [u8; 32],
}

pub(crate) fn repository_dirty_at(root: &Path) -> Result<bool, SessionCtlError> {
    let repository = Repository::open(root).map_err(|_| stage("repository provenance"))?;
    let workdir = repository
        .workdir()
        .ok_or_else(|| stage("repository provenance"))?;
    if repository.is_bare()
        || repository.state() != RepositoryState::Clean
        || !same_file::is_same_file(root, workdir).unwrap_or(false)
    {
        return Err(stage("repository provenance"));
    }

    let mut options = StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_unreadable(true)
        .include_unreadable_as_untracked(true)
        .exclude_submodules(false)
        .update_index(false);
    let statuses = repository
        .statuses(Some(&mut options))
        .map_err(|_| stage("repository provenance"))?;
    Ok(!statuses.is_empty())
}

#[cfg(session_chat_storage_fault_testing)]
pub(crate) fn compiler_provenance() -> Result<CompilerProvenance, SessionCtlError> {
    compiler_provenance_for(std::env::var_os("RUSTC").as_deref())
}

#[cfg(session_chat_storage_fault_testing)]
fn compiler_provenance_for(
    runtime_selection: Option<&OsStr>,
) -> Result<CompilerProvenance, SessionCtlError> {
    let trusted_path = Path::new(env!("SESSION_CHAT_BUILD_RUSTC_PATH"));
    let trusted_path = trusted_path
        .canonicalize()
        .map_err(|_| stage("compiler provenance"))?;
    if let Some(runtime_selection) = runtime_selection {
        let selected = Path::new(runtime_selection);
        if !selected.is_absolute()
            || selected
                .canonicalize()
                .map_err(|_| stage("compiler provenance"))?
                != trusted_path
        {
            return Err(stage("compiler provenance"));
        }
    }

    let expected_digest = decode_sha256(env!("SESSION_CHAT_BUILD_RUSTC_SHA256"))?;
    verify_file_digest(&trusted_path, &expected_digest)?;
    Ok(CompilerProvenance {
        release: env!("SESSION_CHAT_BUILD_RUSTC_RELEASE").to_owned(),
        commit: env!("SESSION_CHAT_BUILD_RUSTC_COMMIT").to_owned(),
        host: env!("SESSION_CHAT_BUILD_RUSTC_HOST").to_owned(),
        digest: expected_digest,
    })
}

#[cfg(session_chat_storage_fault_testing)]
fn verify_file_digest(path: &Path, expected: &[u8; 32]) -> Result<(), SessionCtlError> {
    let mut file = File::open(path).map_err(|_| stage("compiler provenance"))?;
    let mut context = Context::new(&SHA256);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| stage("compiler provenance"))?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
    }
    let actual: [u8; 32] = context
        .finish()
        .as_ref()
        .try_into()
        .map_err(|_| stage("compiler provenance"))?;
    if &actual != expected {
        return Err(stage("compiler provenance"));
    }
    Ok(())
}

#[cfg(session_chat_storage_fault_testing)]
fn decode_sha256(value: &str) -> Result<[u8; 32], SessionCtlError> {
    if value.len() != 64 {
        return Err(stage("compiler provenance"));
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| stage("compiler provenance"))?;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use git2::{IndexAddOption, Signature};

    use super::*;

    fn committed_repository() -> (test_private_dir::PrivateDir, PathBuf) {
        let owner = test_private_dir::PrivateDir::new().expect("private repository fixture");
        let root = owner.path().to_path_buf();
        let repository = Repository::init(&root).expect("initialize repository");
        fs::write(root.join("tracked.txt"), b"tracked\n").expect("write tracked fixture");
        fs::write(root.join(".gitignore"), b"ignored/\n").expect("write ignore fixture");
        let mut index = repository.index().expect("open index");
        index
            .add_all(["tracked.txt", ".gitignore"], IndexAddOption::DEFAULT, None)
            .expect("add fixtures");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repository.find_tree(tree_id).expect("load tree");
        let signature =
            Signature::now("Session Chat", "session-chat@example.invalid").expect("test signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
            .expect("commit fixture");
        drop(tree);
        drop(repository);
        (owner, root)
    }

    #[test]
    fn repository_status_rejects_tracked_staged_and_untracked_changes_but_honors_ignores() {
        let (_owner, root) = committed_repository();
        assert!(!repository_dirty_at(&root).expect("clean repository"));

        fs::write(root.join("tracked.txt"), b"modified\n").expect("modify tracked fixture");
        assert!(repository_dirty_at(&root).expect("modified repository"));
        fs::write(root.join("tracked.txt"), b"tracked\n").expect("restore tracked fixture");

        fs::write(root.join("untracked.txt"), b"untracked\n").expect("write untracked fixture");
        assert!(repository_dirty_at(&root).expect("untracked repository"));
        fs::remove_file(root.join("untracked.txt")).expect("remove untracked fixture");

        let repository = Repository::open(&root).expect("reopen repository");
        let mut index = repository.index().expect("open index");
        fs::write(root.join("tracked.txt"), b"staged\n").expect("write staged fixture");
        index
            .add_path(Path::new("tracked.txt"))
            .expect("stage modified fixture");
        index.write().expect("write staged index");
        assert!(repository_dirty_at(&root).expect("staged repository"));
        drop(index);
        drop(repository);

        let (_ignored_owner, ignored_root) = committed_repository();
        fs::create_dir(ignored_root.join("ignored")).expect("create ignored directory");
        fs::write(ignored_root.join("ignored/output"), b"ignored\n")
            .expect("write ignored fixture");
        assert!(!repository_dirty_at(&ignored_root).expect("ignored repository"));
    }

    #[test]
    #[cfg(session_chat_storage_fault_testing)]
    fn compiler_provenance_rejects_runtime_selection_and_digest_substitution() {
        let provenance = compiler_provenance_for(None).expect("embedded compiler provenance");
        assert!(provenance.digest.iter().any(|byte| *byte != 0));

        let owner = test_private_dir::PrivateDir::new().expect("private compiler fixture");
        let fake = owner
            .path()
            .join(format!("rustc{}", std::env::consts::EXE_SUFFIX));
        fs::write(&fake, b"forged compiler").expect("write forged compiler");
        assert!(compiler_provenance_for(Some(fake.as_os_str())).is_err());
        assert!(verify_file_digest(&fake, &[0_u8; 32]).is_err());
    }
}

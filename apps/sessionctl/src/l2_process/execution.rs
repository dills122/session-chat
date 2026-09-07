//! Execution-time identity: run private snapshots, retain digests, reject source replacement.
use super::*;
const MAX_BINARY: u64 = 256 * 1024 * 1024;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ExecutionIdentity {
    pub(super) verifier: [u8; 32],
    pub(super) producer: [u8; 32],
    pub(super) fault_driver: Option<[u8; 32]>,
}
impl ExecutionIdentity {
    pub(super) fn capture(
        verifier: [u8; 32],
        fault_driver: Option<[u8; 32]>,
    ) -> Result<Self, SessionCtlError> {
        let producer = binary_digest(&std::env::current_exe().map_err(|_| stage("L2 producer"))?)?;
        Ok(Self {
            verifier,
            producer,
            fault_driver,
        })
    }
    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            verifier: [7; 32],
            producer: [8; 32],
            fault_driver: None,
        }
    }
}

fn binary_bytes(path: &Path) -> Result<Vec<u8>, SessionCtlError> {
    if !path.is_absolute() {
        return Err(stage("L2 executable identity"));
    }
    let meta = fs::symlink_metadata(path).map_err(|_| stage("L2 executable identity"))?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.len() == 0
        || meta.len() > MAX_BINARY
    {
        return Err(stage("L2 executable identity"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| stage("L2 executable identity"))?
        .take(MAX_BINARY + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| stage("L2 executable identity"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_BINARY {
        return Err(stage("L2 executable identity"));
    }
    Ok(bytes)
}
pub(super) fn binary_digest(path: &Path) -> Result<[u8; 32], SessionCtlError> {
    digest(&SHA256, &binary_bytes(path)?)
        .as_ref()
        .try_into()
        .map_err(|_| stage("L2 executable identity"))
}

pub(super) struct ExecutableSnapshot {
    _owner: test_private_dir::PrivateDir,
    path: PathBuf,
    source: PathBuf,
    pub(super) digest: [u8; 32],
}
impl ExecutableSnapshot {
    pub(super) fn capture(source: &Path) -> Result<Self, SessionCtlError> {
        let bytes = binary_bytes(source)?;
        let digest = digest(&SHA256, &bytes)
            .as_ref()
            .try_into()
            .map_err(|_| stage("L2 executable identity"))?;
        let owner = test_private_dir::PrivateDir::new().map_err(|_| stage("L2 executable root"))?;
        let snapshot = Self {
            path: owner.path().join("producer.exe"),
            _owner: owner,
            source: source.to_owned(),
            digest,
        };
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&snapshot.path)
            .map_err(|_| stage("L2 executable copy"))?;
        file.write_all(&bytes)
            .map_err(|_| stage("L2 executable copy"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o500))
                .map_err(|_| stage("L2 executable permissions"))?;
        }
        snapshot.verify_source()?;
        Ok(snapshot)
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn verify_source(&self) -> Result<(), SessionCtlError> {
        if binary_digest(&self.source)? != self.digest {
            return Err(stage("L2 executable changed"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_replacement_cannot_change_the_executed_snapshot_or_claimed_digest() {
        let root = test_private_dir::PrivateDir::new().unwrap();
        let source = root.path().join("source");
        fs::write(&source, b"binary A").unwrap();
        let captured = ExecutableSnapshot::capture(&source).unwrap();
        assert_eq!(binary_digest(captured.path()).unwrap(), captured.digest);
        assert!(captured.verify_source().is_ok());
        fs::write(&source, b"binary B").unwrap();
        assert!(captured.verify_source().is_err());
        assert_eq!(fs::read(captured.path()).unwrap(), b"binary A");
        assert_ne!(binary_digest(&source).unwrap(), captured.digest);
    }
    #[test]
    fn verifier_producer_and_separate_fault_driver_are_distinct_roles() {
        let a = ExecutionIdentity::capture([1; 32], Some([2; 32])).unwrap();
        let b = ExecutionIdentity::capture([2; 32], Some([1; 32])).unwrap();
        assert!(a != b);
        assert_eq!(a.fault_driver, Some([2; 32]));
        assert_ne!(a.verifier, a.producer);
    }
}

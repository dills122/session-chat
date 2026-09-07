//! Private, exclusively created directories for test artifacts only.
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Owns one directory and retains its identity for fail-closed cleanup.
pub struct PrivateDir {
    path: PathBuf,
    identity: same_file::Handle,
}
impl PrivateDir {
    /// Creates a random owner-only directory in the system temporary directory.
    pub fn new() -> io::Result<Self> {
        Self::new_in(&std::env::temp_dir())
    }

    /// Creates a random owner-only directory beneath an existing parent.
    pub fn new_in(parent: &Path) -> io::Result<Self> {
        for _ in 0..8 {
            let mut random = [0; 32];
            getrandom::fill(&mut random).map_err(io::Error::other)?;
            let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let path = parent.join(format!("session-chat-test-{name}"));
            match Self::create_at(path) {
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                result => return result,
            }
        }
        Err(io::Error::other("private directory collision bound"))
    }

    fn create_at(path: PathBuf) -> io::Result<Self> {
        create_private_directory(&path)?;
        let identity = same_file::Handle::from_path(&path)?;
        Ok(Self { path, identity })
    }

    /// Returns the owned directory, whose children must remain under this owner.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
fn ordinary_directory(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    metadata.is_dir() && !metadata.file_type().is_symlink()
}
impl Drop for PrivateDir {
    fn drop(&mut self) {
        // Never clean a replacement directory or a link to somebody else's tree.
        if fs::symlink_metadata(&self.path).is_ok_and(|m| ordinary_directory(&m))
            && same_file::Handle::from_path(&self.path).is_ok_and(|h| h == self.identity)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
    };
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // Protected DACL: only the object's owner gets full control; child objects
    // inherit the same owner-rights rule. Applied AT creation, never afterward.
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: terminated UTF-16 input, valid output pointer; Windows allocates
    // descriptor, kept live through CreateDirectoryW and freed with LocalFree.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let created = CreateDirectoryW(path.as_ptr(), &attributes);
        let error = io::Error::last_os_error();
        LocalFree(descriptor);
        if created == 0 { Err(error) } else { Ok(()) }
    }
}

/// Database filename plus the lifetime owner of every SQLite sidecar.
pub struct TestDatabase(pub PathBuf, PrivateDir);
impl TestDatabase {
    /// Creates a fresh namespace; the diagnostic label is never a path component.
    pub fn new(_label: &str) -> Self {
        let owner = PrivateDir::new().expect("private database directory");
        Self(owner.path().join("database.sqlite3"), owner)
    }
    /// Returns the directory that owns the database and all sidecars.
    pub fn directory(&self) -> &Path {
        self.1.path()
    }
    /// Exclusively creates a new artifact; precreated files and links fail closed.
    pub fn write_new(&self, bytes: &[u8]) -> io::Result<()> {
        use io::Write;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.0)?
            .write_all(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exclusive_creation_and_parallel_names() {
        let parent = PrivateDir::new().unwrap();
        let occupied = parent.path().join("occupied");
        fs::create_dir(&occupied).unwrap();
        assert!(PrivateDir::create_at(occupied).is_err());
        let owners: Vec<_> = (0..16)
            .map(|_| std::thread::spawn(PrivateDir::new))
            .collect();
        let owners: Vec<_> = owners
            .into_iter()
            .map(|t| t.join().unwrap().unwrap())
            .collect();
        for (i, owner) in owners.iter().enumerate() {
            assert!(owners[..i].iter().all(|other| owner.path() != other.path()));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(owner.path()).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
        }
    }
    #[test]
    fn sidecars_and_exclusive_artifacts_are_owned() {
        let database = TestDatabase::new("../../ignored");
        let directory = database.directory().to_owned();
        database.write_new(b"first").unwrap();
        assert!(database.write_new(b"clobber").is_err());
        for suffix in ["sqlite3-journal", "sqlite3-wal", "sqlite3-shm"] {
            fs::write(database.0.with_extension(suffix), b"sidecar").unwrap();
        }
        drop(database);
        assert!(!directory.exists());
    }
    #[cfg(windows)]
    #[test]
    fn prepositioned_junction_cannot_redirect_creation_or_cleanup() {
        let parent = PrivateDir::new().unwrap();
        let target = PrivateDir::new().unwrap();
        let link = parent.path().join("junction");
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(target.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!ordinary_directory(&fs::symlink_metadata(&link).unwrap()));
        assert!(PrivateDir::create_at(link.clone()).is_err());
        fs::write(target.path().join("marker"), b"unchanged").unwrap();
        drop(parent);
        assert_eq!(
            fs::read(target.path().join("marker")).unwrap(),
            b"unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepositioned_links_never_modify_the_target_or_redirect_cleanup() {
        use std::os::unix::fs::symlink;
        let parent = PrivateDir::new().unwrap();
        let target = parent.path().join("target");
        fs::write(&target, b"unchanged").unwrap();
        let old = parent
            .path()
            .join("session-chat-sqlcipher-tampered-123-test.sqlite3");
        symlink(&target, &old).unwrap();
        assert!(PrivateDir::create_at(old.clone()).is_err());
        let database = TestDatabase::new("tampered");
        symlink(&target, &database.0).unwrap();
        assert!(database.write_new(b"clobber").is_err());
        drop(database);
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert!(fs::symlink_metadata(old).unwrap().file_type().is_symlink());
        let owned = PrivateDir::new_in(parent.path()).unwrap();
        let moved = parent.path().join("moved");
        fs::rename(owned.path(), &moved).unwrap();
        symlink(parent.path(), owned.path()).unwrap();
        drop(owned);
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
        assert!(moved.exists());
    }
}

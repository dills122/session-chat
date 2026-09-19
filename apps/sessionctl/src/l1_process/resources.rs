//! Private process roots, child lifecycle, and provenance.

use super::super::StageResult;
use super::super::{SessionCtlError, random_nonzero, stage};
use super::ipc::{atomic_write, read_bounded, read_bounded_regular_file};
use super::{
    MAX_CHILD_OUTPUT_BYTES, MAX_GIT_PATH_BYTES, MAX_GIT_REF_BYTES, MAX_LOCKFILE_BYTES,
    MAX_TOOLCHAIN_BYTES, POLL_INTERVAL, ROOT_MARKER,
};
use aws_lc_rs::digest::{SHA256, digest};
use std::ffi::OsStr;
use std::fs;
use std::io::{PipeReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
pub(super) fn create_private_directory(path: &Path) -> Result<(), SessionCtlError> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    builder.create(path).at_stage("process root")
}

pub(super) struct ProcessRoot {
    path: Option<PathBuf>,
    directory: Option<cap_std::fs::Dir>,
}

impl ProcessRoot {
    pub(super) fn new() -> Result<Self, SessionCtlError> {
        Self::create_at(fresh_process_root_path("l1")?)
    }

    pub(super) fn create_at(root: PathBuf) -> Result<Self, SessionCtlError> {
        Self::create_at_with(root, |_| Ok(()))
    }

    pub(super) fn create_at_with(
        root: PathBuf,
        after_create: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<Self, SessionCtlError> {
        if !root.is_absolute() || root.as_os_str().len() > 4_096 || root.exists() {
            return Err(stage("process root"));
        }
        create_private_directory(&root)?;
        after_create(&root).at_stage("process root creation")?;
        let directory = cap_std::fs::Dir::open_ambient_dir(&root, cap_std::ambient_authority())
            .at_stage("process root handle")?;
        validate_new_root_handle(&root, &directory)?;
        let process_root = Self {
            path: Some(root),
            directory: Some(directory),
        };
        atomic_write(
            &process_root.path().join(".sessionctl-l1-root"),
            ROOT_MARKER,
            ROOT_MARKER.len(),
        )?;
        for directory in [
            process_root.path().join("direct"),
            process_root.path().join("relay"),
            process_root.path().join("relay/in"),
            process_root.path().join("relay/out"),
            process_root.path().join("alice"),
        ] {
            create_private_directory(&directory)?;
        }
        Ok(process_root)
    }

    pub(super) fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("process root is unavailable after cleanup")
    }

    pub(super) fn cleanup(&mut self) -> Result<(), SessionCtlError> {
        self.cleanup_with(|_| Ok(()))
    }

    pub(super) fn cleanup_with(
        &mut self,
        before_remove: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<(), SessionCtlError> {
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        validate_root(&path)?;
        before_remove(&path).at_stage("process root removal")?;
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| stage("process root handle"))?;
        remove_directory_contents(directory).at_stage("process root removal")?;
        #[cfg(not(windows))]
        {
            let removal_handle = directory
                .try_clone()
                .at_stage("process root removal handle")?;
            remove_open_directory(removal_handle, &path).at_stage("process root removal")?;
        }
        #[cfg(windows)]
        {
            let removal_handle = self
                .directory
                .take()
                .ok_or_else(|| stage("process root handle"))?;
            remove_open_directory(removal_handle, &path).at_stage("process root removal")?;
        }
        self.directory = None;
        self.path = None;
        Ok(())
    }
}

pub(super) fn validate_new_root_handle(
    path: &Path,
    directory: &cap_std::fs::Dir,
) -> Result<(), SessionCtlError> {
    let metadata = fs::symlink_metadata(path).at_stage("process root identity")?;
    if !metadata.file_type().is_dir() {
        return Err(stage("process root identity"));
    }
    let retained = directory
        .try_clone()
        .map(cap_std::fs::Dir::into_std_file)
        .and_then(same_file::Handle::from_file)
        .at_stage("process root identity")?;
    let named = same_file::Handle::from_path(path).at_stage("process root identity")?;
    if retained != named {
        return Err(stage("process root identity"));
    }
    if directory
        .entries()
        .at_stage("process root identity")?
        .next()
        .transpose()
        .at_stage("process root identity")?
        .is_some()
    {
        return Err(stage("process root identity"));
    }
    Ok(())
}

pub(super) fn remove_directory_contents(directory: &cap_std::fs::Dir) -> std::io::Result<()> {
    let entries = directory
        .entries()?
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    for entry in entries {
        let name = entry.file_name();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let child = directory.open_dir(&name)?;
            remove_directory_contents(&child)?;
            drop(child);
            directory.remove_dir(&name)?;
        } else {
            directory.remove_file(&name)?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn remove_open_directory(
    directory: cap_std::fs::Dir,
    _path: &Path,
) -> std::io::Result<()> {
    directory.remove_open_dir()
}

#[cfg(windows)]
pub(super) fn remove_open_directory(
    directory: cap_std::fs::Dir,
    path: &Path,
) -> std::io::Result<()> {
    // cap-std holds this handle without FILE_SHARE_DELETE, so the pathname
    // cannot be rebound while contents are removed. Only the final empty-dir
    // removal occurs after releasing that lock; it can never recurse into a
    // replacement tree.
    drop(directory);
    fs::remove_dir(path)
}

impl Drop for ProcessRoot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(super) fn fresh_process_root_path(label: &str) -> Result<PathBuf, SessionCtlError> {
    let identifier: [u8; 16] = random_nonzero()?;
    let name = format!(
        "session-chat-{label}-{}",
        identifier
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    Ok(std::env::temp_dir().join(name))
}

pub(super) fn validate_root(root: &Path) -> Result<(), SessionCtlError> {
    for directory in ["", "direct", "relay", "relay/in", "relay/out", "alice"] {
        let metadata = match fs::symlink_metadata(root.join(directory)) {
            Ok(metadata) => metadata,
            // Creation failures still need to clean a partially built marked root.
            Err(error) if !directory.is_empty() && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(_) => return Err(stage("process root validation")),
        };
        if !metadata.file_type().is_dir() {
            return Err(stage("process root validation"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(stage("process root permissions"));
            }
        }
    }
    if !root.is_absolute()
        || root.as_os_str().len() > 4_096
        || read_bounded_file(&root.join(".sessionctl-l1-root"), ROOT_MARKER.len()).as_deref()
            != Some(ROOT_MARKER)
    {
        return Err(stage("process root validation"));
    }
    Ok(())
}

pub(super) fn two_terminal_done_path(root: &Path) -> PathBuf {
    root.join("join-complete")
}

pub(super) struct ManagedChild {
    role: &'static str,
    child: Option<Child>,
}

impl ManagedChild {
    pub(super) const fn new(role: &'static str, child: Child) -> Self {
        Self {
            role,
            child: Some(child),
        }
    }

    pub(super) fn child_mut(&mut self) -> Result<&mut Child, SessionCtlError> {
        self.child.as_mut().ok_or_else(|| stage("process child"))
    }

    pub(super) fn terminate_and_reap(&mut self) -> std::io::Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let result = match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => match child.kill() {
                Ok(()) => child.wait().map(|_| ()),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                    child.wait().map(|_| ())
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };
        if result.is_err() {
            self.child = Some(child);
        }
        result
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

pub(super) struct ChildSet(pub(super) Vec<ManagedChild>);

impl ChildSet {
    pub(super) const fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn spawn(
        &mut self,
        executable: &Path,
        role: &'static str,
        root: &Path,
    ) -> Result<(), SessionCtlError> {
        self.spawn_with_io(executable, role, root, Stdio::null(), Stdio::piped())
    }

    pub(super) fn spawn_private_writer(
        &mut self,
        executable: &Path,
        role: &'static str,
        root: &Path,
    ) -> Result<PipeReader, SessionCtlError> {
        let (reader, writer) = std::io::pipe().at_stage("process private pipe")?;
        // stderr is a dedicated secret channel for this role, never collected
        // as diagnostics. The service and Bob receive neither pipe endpoint.
        self.spawn_with_io(executable, role, root, Stdio::null(), writer.into())?;
        Ok(reader)
    }

    pub(super) fn spawn_with_io(
        &mut self,
        executable: &Path,
        role: &'static str,
        root: &Path,
        input: Stdio,
        error_output: Stdio,
    ) -> Result<(), SessionCtlError> {
        let child = Command::new(executable)
            .arg("--internal-role")
            .arg(role)
            .arg(root)
            .stdin(input)
            .stdout(Stdio::piped())
            .stderr(error_output)
            .spawn()
            .at_stage("process spawn")?;
        self.0.push(ManagedChild::new(role, child));
        Ok(())
    }

    pub(super) fn wait_role(
        &mut self,
        role: &'static str,
        timeout: Duration,
    ) -> Result<ChildOutput, SessionCtlError> {
        self.wait_role_with(role, timeout, Child::try_wait)
    }

    pub(super) fn wait_role_with(
        &mut self,
        role: &'static str,
        timeout: Duration,
        mut try_wait: impl FnMut(&mut Child) -> std::io::Result<Option<ExitStatus>>,
    ) -> Result<ChildOutput, SessionCtlError> {
        let index = self
            .0
            .iter()
            .position(|child| child.role == role)
            .ok_or_else(|| stage("process child"))?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("process child deadline"))?;
        loop {
            let status = try_wait(self.0[index].child_mut()?).at_stage("process child wait")?;
            if let Some(status) = status {
                let managed = self.0.remove(index);
                return collect_child_output(managed, status);
            }
            if Instant::now() >= deadline {
                return Err(stage("process child timeout"));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    pub(super) fn cleanup(&mut self) -> Result<(), SessionCtlError> {
        let mut cleanup_failed = false;
        for managed in &mut self.0 {
            cleanup_failed |= managed.terminate_and_reap().is_err();
        }
        self.0.retain(|managed| managed.child.is_some());
        if cleanup_failed || !self.0.is_empty() {
            return Err(stage("process child cleanup"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for ChildSet {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(super) struct ChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub(super) fn collect_child_output(
    mut managed: ManagedChild,
    status: ExitStatus,
) -> Result<ChildOutput, SessionCtlError> {
    let child = managed.child_mut()?;
    let stdout = child
        .stdout
        .take()
        .map(|stdout| read_bounded(stdout, MAX_CHILD_OUTPUT_BYTES))
        .transpose()?
        .unwrap_or_default();
    let stderr = child
        .stderr
        .take()
        .map(|stderr| read_optional_bounded(stderr, MAX_CHILD_OUTPUT_BYTES))
        .transpose()?
        .unwrap_or_default();
    Ok(ChildOutput {
        status,
        stdout,
        stderr,
    })
}

pub(super) fn read_optional_bounded(
    mut file: impl Read,
    maximum: usize,
) -> Result<Vec<u8>, SessionCtlError> {
    let mut bytes = Vec::with_capacity(maximum);
    Read::by_ref(&mut file)
        .take(u64::try_from(maximum).map_err(|_| stage("process output"))? + 1)
        .read_to_end(&mut bytes)
        .at_stage("process output")?;
    if bytes.len() > maximum {
        return Err(stage("process output bound"));
    }
    Ok(bytes)
}

pub(super) fn require_child_output(
    output: &ChildOutput,
    expected: &[u8],
) -> Result<(), SessionCtlError> {
    if !output.status.success() || !output.stderr.is_empty() || output.stdout != expected {
        return Err(stage("process child result"));
    }
    Ok(())
}

pub(super) fn direct_invitation_path(root: &Path) -> PathBuf {
    root.join("direct/invitation.v2")
}

pub(super) fn foreign_invitation_path(root: &Path) -> PathBuf {
    root.join("direct/foreign-invitation.v2")
}

pub(super) fn hostile_case_path(root: &Path) -> PathBuf {
    root.join("direct/hostile.case")
}

pub(super) fn database_path(root: &Path) -> PathBuf {
    root.join("alice/owner.sqlite3")
}

pub(super) fn relay_in(root: &Path, sequence: u8) -> PathBuf {
    root.join("relay/in").join(frame_name(sequence))
}

pub(super) fn relay_out(root: &Path, sequence: u8) -> PathBuf {
    root.join("relay/out").join(frame_name(sequence))
}

pub(super) fn frame_name(sequence: u8) -> &'static OsStr {
    match sequence {
        1 => OsStr::new("001.frame"),
        2 => OsStr::new("002.frame"),
        3 => OsStr::new("003.frame"),
        4 => OsStr::new("004.frame"),
        5 => OsStr::new("005.frame"),
        6 => OsStr::new("006.frame"),
        7 => OsStr::new("007.frame"),
        _ => OsStr::new("invalid.frame"),
    }
}

pub(super) fn unix_now() -> Result<u64, SessionCtlError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .at_stage("process wall clock")
        .map(|duration| duration.as_secs())
}

pub(super) fn repository_root() -> Option<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()
        .map(Path::to_path_buf)
}

pub(super) fn git_commit_at(repository_root: &Path) -> String {
    resolve_git_commit(repository_root).unwrap_or_else(|| String::from("unavailable"))
}

/// Resolves bounded Git commit metadata for the retained conformance harness.
///
/// This checkout-independent integration seam is not a product metadata API.
#[doc(hidden)]
pub fn resolve_l1_process_git_commit(repository_root: &Path) -> Option<String> {
    resolve_git_commit(repository_root)
}

pub(super) fn lock_digest_at(repository_root: &Path) -> String {
    read_bounded_file(&repository_root.join("Cargo.lock"), MAX_LOCKFILE_BYTES)
        .map(|bytes| hex(digest(&SHA256, &bytes).as_ref()))
        .unwrap_or_else(|| String::from("unavailable"))
}

pub(super) fn pinned_toolchain_at(repository_root: &Path) -> String {
    let Some(encoded) = read_bounded_file(
        &repository_root.join("rust-toolchain.toml"),
        MAX_TOOLCHAIN_BYTES,
    ) else {
        return String::from("unavailable");
    };
    let Ok(contents) = String::from_utf8(encoded) else {
        return String::from("unavailable");
    };
    contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = \"")?.strip_suffix('"'))
        .filter(|channel| {
            !channel.is_empty()
                && channel.len() <= 32
                && channel
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        })
        .map(str::to_owned)
        .unwrap_or_else(|| String::from("unavailable"))
}

pub(super) fn read_bounded_file(path: &Path, maximum: usize) -> Option<Vec<u8>> {
    read_bounded_regular_file(path, maximum).ok()
}

pub(super) fn resolve_git_commit(repository_root: &Path) -> Option<String> {
    let git_marker = repository_root.join(".git");
    let git_directory = if git_marker.is_dir() {
        git_marker
    } else {
        let marker = String::from_utf8(read_bounded_file(&git_marker, MAX_GIT_PATH_BYTES)?).ok()?;
        let path = marker.trim().strip_prefix("gitdir: ")?;
        let path = Path::new(path);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            repository_root.join(path)
        }
    };
    let head = String::from_utf8(read_bounded_file(
        &git_directory.join("HEAD"),
        MAX_GIT_REF_BYTES,
    )?)
    .ok()?;
    if let Some(commit) = parse_git_commit(head.trim()) {
        return Some(commit);
    }
    let reference = head.trim().strip_prefix("ref: ")?;
    let reference_path = Path::new(reference);
    if !reference.starts_with("refs/")
        || reference_path.is_absolute()
        || !reference_path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let common_directory = read_bounded_file(&git_directory.join("commondir"), MAX_GIT_PATH_BYTES)
        .and_then(|encoded| String::from_utf8(encoded).ok())
        .map_or_else(
            || git_directory.clone(),
            |path| git_directory.join(path.trim()),
        );
    [git_directory, common_directory]
        .into_iter()
        .find_map(|directory| {
            let encoded = read_bounded_file(&directory.join(reference_path), MAX_GIT_REF_BYTES)?;
            let value = String::from_utf8(encoded).ok()?;
            parse_git_commit(value.trim())
        })
}

pub(super) fn parse_git_commit(value: &str) -> Option<String> {
    (value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

#[cfg(test)]
pub(super) fn bounded_command_status(
    mut command: Command,
    timeout: Duration,
) -> Option<ExitStatus> {
    let deadline = Instant::now().checked_add(timeout)?;
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut managed = ManagedChild::new("metadata", child);
    loop {
        let wait_result = match managed.child_mut() {
            Ok(child) => child.try_wait(),
            Err(_) => {
                let _ = managed.terminate_and_reap();
                return None;
            }
        };
        match wait_result {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => {
                let _ = managed.terminate_and_reap();
                return None;
            }
        }
        if Instant::now() >= deadline {
            let _ = managed.terminate_and_reap();
            return None;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

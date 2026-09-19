//! Private process roots, owned files, child supervision, and pipes.

use super::*;

pub(super) struct AutoContinueBarrier;

impl BarrierTransport for AutoContinueBarrier {
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure> {
        let checkpoint = ControlFrame::decode(&encoded).map_err(|_| BarrierFailure::Rejected)?;
        if checkpoint.kind() != FrameKind::Checkpoint || checkpoint.role() != Role::Writer {
            return Err(BarrierFailure::Rejected);
        }
        Ok(checkpoint.acknowledgement().encode())
    }
}

#[derive(Default)]
pub(super) struct StdioBarrier(std::sync::Mutex<()>);

impl BarrierTransport for StdioBarrier {
    fn exchange(
        &self,
        encoded: [u8; CONTROL_FRAME_BYTES],
    ) -> Result<[u8; CONTROL_FRAME_BYTES], BarrierFailure> {
        let _guard = self.0.lock().map_err(|_| BarrierFailure::Rejected)?;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&encoded)
            .and_then(|()| stdout.flush())
            .map_err(|_| BarrierFailure::Rejected)?;
        let mut acknowledgement = [0_u8; CONTROL_FRAME_BYTES];
        std::io::stdin()
            .lock()
            .read_exact(&mut acknowledgement)
            .map_err(|_| BarrierFailure::Rejected)?;
        Ok(acknowledgement)
    }
}

pub(super) struct ProcessRoot(Option<PathBuf>);

impl ProcessRoot {
    pub(super) fn new() -> Result<Self, SessionCtlError> {
        for _ in 0..8 {
            let identifier: [u8; 16] = random_nonzero()?;
            let root = std::env::temp_dir().join(format!("session-chat-l2-{}", hex(&identifier)));
            match fs::create_dir(&root) {
                Ok(()) => {
                    set_private_directory_permissions(&root)?;
                    write_owned_file(&root.join(ROOT_MARKER_NAME), ROOT_MARKER, false)?;
                    return Ok(Self(Some(root)));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(stage("L2 root")),
            }
        }
        Err(stage("L2 root"))
    }

    pub(super) fn path(&self) -> &Path {
        self.0
            .as_deref()
            .expect("L2 root unavailable after cleanup")
    }

    pub(super) fn cleanup(&mut self) -> Result<(), SessionCtlError> {
        self.cleanup_with(|path| fs::remove_dir_all(path))
    }

    pub(super) fn cleanup_with(
        &mut self,
        remove: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<(), SessionCtlError> {
        let Some(path) = self.0.as_deref() else {
            return Ok(());
        };
        validate_root_tree(path)?;
        remove(path).map_err(|_| stage("L2 root cleanup"))?;
        self.0 = None;
        Ok(())
    }
}

impl Drop for ProcessRoot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(super) fn validate_root(root: &Path) -> Result<(), SessionCtlError> {
    if !root.is_absolute() || root.as_os_str().len() > 4_096 {
        return Err(stage("L2 root validation"));
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| stage("L2 root validation"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(stage("L2 root validation"));
    }
    let marker = root.join(ROOT_MARKER_NAME);
    if read_owned_file(&marker, ROOT_MARKER.len())?.as_slice() != ROOT_MARKER {
        return Err(stage("L2 root validation"));
    }
    Ok(())
}

pub(super) fn validate_root_tree(root: &Path) -> Result<(), SessionCtlError> {
    validate_root(root)?;
    let canonical_root = root
        .canonicalize()
        .map_err(|_| stage("L2 root validation"))?;
    let entries: Vec<_> = fs::read_dir(root)
        .map_err(|_| stage("L2 root validation"))?
        .collect::<Result<_, _>>()
        .map_err(|_| stage("L2 root validation"))?;
    if entries.len() > MAX_CASE_ENTRIES {
        return Err(stage("L2 root validation"));
    }
    for entry in entries {
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| stage("L2 root validation"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(stage("L2 root validation"));
        }
        let canonical = entry
            .path()
            .canonicalize()
            .map_err(|_| stage("L2 root validation"))?;
        if !canonical.starts_with(&canonical_root) {
            return Err(stage("L2 root validation"));
        }
    }
    Ok(())
}

pub(super) fn write_owned_file(
    path: &Path,
    bytes: &[u8],
    secret: bool,
) -> Result<(), SessionCtlError> {
    write_bounded_owned_file(path, bytes, secret, 4_096)
}

pub(super) fn write_bounded_owned_file(
    path: &Path,
    bytes: &[u8],
    secret: bool,
    maximum: usize,
) -> Result<(), SessionCtlError> {
    if bytes.len() > maximum || path.parent().is_none() {
        return Err(stage("L2 file"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| stage("L2 file"))?;
    if secret {
        set_private_file_permissions(path)?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| stage("L2 file"))
}

pub(super) fn read_bounded_owned_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, SessionCtlError> {
    validate_owned_file(path, None)?;
    let metadata = fs::metadata(path).map_err(|_| stage("L2 file"))?;
    if metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(stage("L2 file"));
    }
    let file = File::open(path).map_err(|_| stage("L2 file"))?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| stage("L2 file"))?);
    file.take(
        u64::try_from(maximum)
            .map_err(|_| stage("L2 file"))?
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)
    .map_err(|_| stage("L2 file"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(stage("L2 file"));
    }
    Ok(bytes)
}

pub(super) fn read_bounded_owned_file_once(
    path: &Path,
    maximum: usize,
    cleanup_stage: &'static str,
) -> Result<Zeroizing<Vec<u8>>, SessionCtlError> {
    let bytes = Zeroizing::new(read_bounded_owned_file(path, maximum)?);
    fs::remove_file(path).map_err(|_| stage(cleanup_stage))?;
    Ok(bytes)
}

pub(super) fn read_owned_file(path: &Path, expected: usize) -> Result<Vec<u8>, SessionCtlError> {
    validate_owned_file(path, Some(expected))?;
    let file = File::open(path).map_err(|_| stage("L2 file"))?;
    let mut bytes = Vec::with_capacity(expected);
    file.take(u64::try_from(expected + 1).map_err(|_| stage("L2 file"))?)
        .read_to_end(&mut bytes)
        .map_err(|_| stage("L2 file"))?;
    if bytes.len() != expected {
        return Err(stage("L2 file"));
    }
    Ok(bytes)
}

pub(super) fn validate_owned_file(
    path: &Path,
    expected: Option<usize>,
) -> Result<(), SessionCtlError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| stage("L2 file"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(stage("L2 file"));
    }
    if expected.is_some_and(|expected| metadata.len() != expected as u64) {
        return Err(stage("L2 file"));
    }
    Ok(())
}

pub(super) fn read_case_config(root: &Path) -> Result<CaseConfig, SessionCtlError> {
    CaseConfig::decode(&read_owned_file(
        &root.join(CASE_CONFIG_NAME),
        CASE_CONFIG_BYTES,
    )?)
}

pub(super) fn read_key(
    root: &Path,
    name: &str,
) -> Result<Zeroizing<[u8; KEY_BYTES]>, SessionCtlError> {
    let path = root.join(name);
    let mut bytes = Zeroizing::new(read_owned_file(&path, KEY_BYTES)?);
    fs::remove_file(&path).map_err(|_| stage("L2 key cleanup"))?;
    let key = Zeroizing::new(bytes.as_slice().try_into().map_err(|_| stage("L2 key"))?);
    bytes.zeroize();
    Ok(key)
}

#[cfg(unix)]
pub(super) fn set_private_directory_permissions(path: &Path) -> Result<(), SessionCtlError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| stage("L2 root permissions"))
}

#[cfg(not(unix))]
pub(super) fn set_private_directory_permissions(_path: &Path) -> Result<(), SessionCtlError> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn set_private_file_permissions(path: &Path) -> Result<(), SessionCtlError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| stage("L2 file permissions"))
}

#[cfg(not(unix))]
pub(super) fn set_private_file_permissions(_path: &Path) -> Result<(), SessionCtlError> {
    Ok(())
}

pub(super) struct ManagedChild {
    pub(super) child: Option<Child>,
    pub(super) stdin: Option<ChildStdin>,
    pub(super) stdout: PipeReader,
    pub(super) stderr: PipeReader,
}

impl ManagedChild {
    pub(super) fn spawn(
        executable: &Path,
        role: &str,
        root: &Path,
        interactive: bool,
    ) -> Result<Self, SessionCtlError> {
        let mut command = Command::new(executable);
        command
            .args([OsStr::new("--internal-role"), OsStr::new(role)])
            .arg(root)
            .stdin(if interactive {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        sanitize_environment(&mut command);
        Self::spawn_command(command)
    }

    pub(super) fn spawn_command(mut command: Command) -> Result<Self, SessionCtlError> {
        let mut child = command.spawn().map_err(|_| stage("L2 spawn"))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or_else(|| stage("L2 stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| stage("L2 stderr"))?;
        Ok(Self {
            child: Some(child),
            stdin,
            stdout: PipeReader::new(stdout),
            stderr: PipeReader::new(stderr),
        })
    }

    pub(super) fn write_stdin(&mut self, bytes: &[u8]) -> Result<(), SessionCtlError> {
        self.stdin
            .as_mut()
            .ok_or_else(|| stage("L2 stdin"))?
            .write_all(bytes)
            .and_then(|()| self.stdin.as_mut().expect("stdin checked").flush())
            .map_err(|_| stage("L2 stdin"))
    }

    pub(super) fn close_stdin(&mut self) {
        self.stdin.take();
    }

    pub(super) fn wait(&mut self, timeout: Duration) -> Result<ExitStatus, SessionCtlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("L2 child deadline"))?;
        loop {
            let child = self.child.as_mut().ok_or_else(|| stage("L2 child"))?;
            if let Some(status) = child.try_wait().map_err(|_| stage("L2 child wait"))? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(stage("L2 child timeout"));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    pub(super) fn terminate_and_reap(&mut self) -> Result<(), SessionCtlError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if child
            .try_wait()
            .map_err(|_| stage("L2 child termination"))?
            .is_some()
        {
            return Err(stage("L2 child escaped barrier"));
        }
        child.kill().map_err(|_| stage("L2 child termination"))?;
        self.stdin.take();
        child.wait().map_err(|_| stage("L2 child reap"))?;
        Ok(())
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        self.stdin.take();
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(super) enum PipeMessage {
    Bytes(Vec<u8>),
    Eof,
    OverLimit,
    ReadFailed,
}

pub(super) struct PipeReader {
    pub(super) receiver: Receiver<PipeMessage>,
    pub(super) join: Option<JoinHandle<()>>,
    pub(super) buffered: Vec<u8>,
    pub(super) eof: bool,
}

impl PipeReader {
    pub(super) fn new(mut reader: impl Read + Send + 'static) -> Self {
        let (sender, receiver) = mpsc::channel();
        let join = thread::spawn(move || {
            let mut total = 0_usize;
            loop {
                let mut chunk = [0_u8; 64];
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = sender.send(PipeMessage::Eof);
                        return;
                    }
                    Ok(read) if total.saturating_add(read) <= MAX_CHILD_OUTPUT_BYTES => {
                        total += read;
                        if sender
                            .send(PipeMessage::Bytes(chunk[..read].to_vec()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    Ok(_) => {
                        let _ = sender.send(PipeMessage::OverLimit);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        let _ = sender.send(PipeMessage::ReadFailed);
                        return;
                    }
                }
            }
        });
        Self {
            receiver,
            join: Some(join),
            buffered: Vec::new(),
            eof: false,
        }
    }

    pub(super) fn read_exact_frame(
        &mut self,
        expected: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, SessionCtlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("L2 output deadline"))?;
        while self.buffered.len() < expected && !self.eof {
            self.receive(deadline, "L2 frame timeout")?;
            if self.buffered.len() > expected {
                return Err(stage("L2 output bound"));
            }
        }
        if self.buffered.len() != expected {
            return Err(stage("L2 output frame"));
        }
        Ok(std::mem::take(&mut self.buffered))
    }

    pub(super) fn require_empty(&mut self, timeout: Duration) -> Result<(), SessionCtlError> {
        if self.collect(timeout)?.is_empty() {
            Ok(())
        } else {
            Err(stage("L2 unexpected child output"))
        }
    }

    pub(super) fn collect(&mut self, timeout: Duration) -> Result<Vec<u8>, SessionCtlError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| stage("L2 output deadline"))?;
        while !self.eof {
            self.receive(deadline, "L2 output timeout")?;
        }
        Ok(std::mem::take(&mut self.buffered))
    }

    pub(super) fn receive(
        &mut self,
        deadline: Instant,
        timeout_stage: &'static str,
    ) -> Result<(), SessionCtlError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| stage(timeout_stage))?;
        match self.receiver.recv_timeout(remaining) {
            Ok(PipeMessage::Bytes(bytes)) => {
                if self.buffered.len().saturating_add(bytes.len()) > MAX_CHILD_OUTPUT_BYTES {
                    return Err(stage("L2 output bound"));
                }
                self.buffered.extend_from_slice(&bytes);
                Ok(())
            }
            Ok(PipeMessage::Eof) => {
                self.eof = true;
                Ok(())
            }
            Ok(PipeMessage::OverLimit) => Err(stage("L2 output bound")),
            Ok(PipeMessage::ReadFailed) => Err(stage("L2 output read")),
            Err(RecvTimeoutError::Disconnected) => Err(stage("L2 output disconnected")),
            Err(RecvTimeoutError::Timeout) => Err(stage(timeout_stage)),
        }
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        if self.eof
            && let Some(join) = self.join.take()
        {
            let _ = join.join();
        } else {
            self.join.take();
        }
    }
}

pub(super) fn sanitize_environment(command: &mut Command) {
    command.env_clear();
    for name in ["PATH", "TMPDIR", "SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name).filter(|value| value.len() <= 4_096) {
            command.env(name, value);
        }
    }
}

pub(super) fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

pub(super) fn git_dirty_at(root: &Path) -> Option<bool> {
    repository_dirty_at(root).ok()
}

pub(super) fn pinned_toolchain_at(root: &Path) -> Option<String> {
    let bytes =
        read_bounded_repository_file(&root.join("rust-toolchain.toml"), MAX_TOOLCHAIN_BYTES)?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let channel = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("channel = \"")?.strip_suffix('"'))?;
    (!channel.is_empty()
        && channel.len() <= 64
        && channel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    .then(|| channel.to_owned())
}

pub(super) fn lock_digest_at(root: &Path) -> Option<String> {
    let bytes = read_bounded_repository_file(&root.join("Cargo.lock"), MAX_LOCKFILE_BYTES)?;
    Some(hex(digest(&SHA256, &bytes).as_ref()))
}

pub(super) fn read_bounded_repository_file(path: &Path, maximum: usize) -> Option<Vec<u8>> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).ok()?);
    file.take(u64::try_from(maximum).ok()?.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= maximum).then_some(bytes)
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

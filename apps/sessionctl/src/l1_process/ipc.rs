//! Bounded L1 IPC framing and channel files.

use super::super::StageResult;
use super::super::{SessionCtlError, stage};
use super::{
    EXPECTED_FRAMES, IPC_HEADER_BYTES, IPC_LENGTH_BYTES, IPC_MAGIC, IPC_VERSION,
    MAX_IPC_FRAME_BYTES, MAX_IPC_PARTS, POLL_INTERVAL,
};
use session_protocol::{
    LocalWelcomeDepositEndpoint, MAX_WIRE_OBJECT_BYTES, OpaqueEnvelope, ProtectedJoinRequest,
};
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FrameKind {
    ProtectedJoin = 1,
    WelcomeDeposit = 2,
    OpaqueEnvelope = 3,
}
impl TryFrom<u8> for FrameKind {
    type Error = SessionCtlError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ProtectedJoin),
            2 => Ok(Self::WelcomeDeposit),
            3 => Ok(Self::OpaqueEnvelope),
            _ => Err(stage("IPC kind")),
        }
    }
}

pub(super) struct IpcFrame {
    kind: FrameKind,
    sequence: u8,
    parts: Vec<Vec<u8>>,
}

impl IpcFrame {
    pub(super) fn new(
        kind: FrameKind,
        sequence: u8,
        parts: Vec<Vec<u8>>,
    ) -> Result<Self, SessionCtlError> {
        let expected_parts = match kind {
            FrameKind::WelcomeDeposit => 2,
            FrameKind::ProtectedJoin | FrameKind::OpaqueEnvelope => 1,
        };
        if !(1..=EXPECTED_FRAMES).contains(&sequence)
            || parts.len() != expected_parts
            || parts
                .iter()
                .any(|part| part.is_empty() || part.len() > MAX_WIRE_OBJECT_BYTES)
        {
            return Err(stage("IPC frame"));
        }
        validate_wire_parts(kind, &parts)?;
        Ok(Self {
            kind,
            sequence,
            parts,
        })
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, SessionCtlError> {
        if encoded.len() < IPC_HEADER_BYTES || encoded.len() > MAX_IPC_FRAME_BYTES {
            return Err(stage("IPC frame"));
        }
        if &encoded[..8] != IPC_MAGIC || encoded[8] != IPC_VERSION {
            return Err(stage("IPC frame"));
        }
        let kind = FrameKind::try_from(encoded[9])?;
        let sequence = encoded[10];
        let part_count = usize::from(encoded[11]);
        if part_count == 0 || part_count > MAX_IPC_PARTS {
            return Err(stage("IPC frame"));
        }
        let mut cursor = IPC_HEADER_BYTES;
        let mut parts = Vec::with_capacity(part_count);
        for _ in 0..part_count {
            let length_end = cursor
                .checked_add(IPC_LENGTH_BYTES)
                .ok_or_else(|| stage("IPC frame"))?;
            let length_bytes: [u8; 4] = encoded
                .get(cursor..length_end)
                .ok_or_else(|| stage("IPC frame"))?
                .try_into()
                .map_err(|_| stage("IPC frame"))?;
            let length = usize::try_from(u32::from_be_bytes(length_bytes))
                .map_err(|_| stage("IPC frame"))?;
            let part_end = length_end
                .checked_add(length)
                .ok_or_else(|| stage("IPC frame"))?;
            let part = encoded
                .get(length_end..part_end)
                .ok_or_else(|| stage("IPC frame"))?;
            parts.push(part.to_vec());
            cursor = part_end;
        }
        if cursor != encoded.len() {
            return Err(stage("IPC frame"));
        }
        let frame = Self::new(kind, sequence, parts)?;
        if frame.encode()? != encoded {
            return Err(stage("IPC canonical encoding"));
        }
        Ok(frame)
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, SessionCtlError> {
        let mut encoded = Vec::with_capacity(MAX_IPC_FRAME_BYTES.min(
            IPC_HEADER_BYTES
                + (self.parts.len() * IPC_LENGTH_BYTES)
                + self.parts.iter().map(Vec::len).sum::<usize>(),
        ));
        encoded.extend_from_slice(IPC_MAGIC);
        encoded.push(IPC_VERSION);
        encoded.push(self.kind as u8);
        encoded.push(self.sequence);
        encoded.push(u8::try_from(self.parts.len()).map_err(|_| stage("IPC frame"))?);
        for part in &self.parts {
            encoded.extend_from_slice(
                &u32::try_from(part.len())
                    .map_err(|_| stage("IPC frame"))?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(part);
        }
        if encoded.len() > MAX_IPC_FRAME_BYTES {
            return Err(stage("IPC frame"));
        }
        Ok(encoded)
    }

    pub(super) fn require(
        self,
        kind: FrameKind,
        sequence: u8,
    ) -> Result<Vec<Vec<u8>>, SessionCtlError> {
        if self.kind != kind || self.sequence != sequence {
            return Err(stage("IPC schedule"));
        }
        Ok(self.parts)
    }
}

pub(super) fn validate_wire_parts(
    kind: FrameKind,
    parts: &[Vec<u8>],
) -> Result<(), SessionCtlError> {
    match kind {
        FrameKind::ProtectedJoin => {
            ProtectedJoinRequest::decode_canonical(&parts[0]).at_stage("IPC protected join")?;
        }
        FrameKind::WelcomeDeposit => {
            LocalWelcomeDepositEndpoint::decode_canonical(&parts[0])
                .at_stage("IPC Welcome endpoint")?;
            OpaqueEnvelope::decode_canonical(&parts[1]).at_stage("IPC Welcome envelope")?;
        }
        FrameKind::OpaqueEnvelope => {
            OpaqueEnvelope::decode_canonical(&parts[0]).at_stage("IPC opaque envelope")?;
        }
    }
    Ok(())
}
pub(super) fn write_frame(path: &Path, frame: IpcFrame) -> Result<(), SessionCtlError> {
    atomic_write(path, &frame.encode()?, MAX_IPC_FRAME_BYTES)
}

pub(super) fn atomic_write(
    path: &Path,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), SessionCtlError> {
    if bytes.is_empty() || bytes.len() > maximum || path.exists() {
        return Err(stage("process channel write"));
    }
    let temporary = path.with_extension("partial");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).at_stage("process channel write")?;
    file.write_all(bytes).at_stage("process channel write")?;
    file.sync_all().at_stage("process channel write")?;
    drop(file);
    fs::rename(&temporary, path).at_stage("process channel publish")?;
    Ok(())
}

pub(super) fn read_bounded_wait(
    path: &Path,
    maximum: usize,
    timeout: Duration,
) -> Result<Vec<u8>, SessionCtlError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| stage("process channel deadline"))?;
    loop {
        if Instant::now() >= deadline {
            return Err(stage("process channel timeout"));
        }
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let bytes = read_bounded_regular_file(path, maximum)?;
                if Instant::now() >= deadline {
                    return Err(stage("process channel timeout"));
                }
                return Ok(bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if Instant::now() >= deadline {
                    return Err(stage("process channel timeout"));
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return Err(stage("process channel read")),
        }
    }
}

pub(super) fn read_bounded(
    mut file: impl Read,
    maximum: usize,
) -> Result<Vec<u8>, SessionCtlError> {
    let limit = u64::try_from(maximum)
        .map_err(|_| stage("process channel bound"))?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(4_096));
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .at_stage("process channel read")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(stage("process channel bound"));
    }
    Ok(bytes)
}

pub(super) fn read_bounded_regular_file(
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, SessionCtlError> {
    let before = fs::symlink_metadata(path).at_stage("network invitation metadata")?;
    if !before.file_type().is_file()
        || before.len() == 0
        || before.len() > u64::try_from(maximum).map_err(|_| stage("network invitation bound"))?
    {
        return Err(stage("network invitation file"));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path).at_stage("network invitation read")?;
    let after = file.metadata().at_stage("network invitation metadata")?;
    if !after.file_type().is_file()
        || after.len() != before.len()
        || after.len() == 0
        || after.len() > u64::try_from(maximum).map_err(|_| stage("network invitation bound"))?
    {
        return Err(stage("network invitation file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(stage("network invitation file"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if before.file_attributes() & 0x400 != 0 || after.file_attributes() & 0x400 != 0 {
            return Err(stage("network invitation file"));
        }
    }
    read_bounded(file, maximum)
}

use std::{
    fs::{self, File},
    io,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        INHERITED_ACE, IsWellKnownSid, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        WinCreatorOwnerRightsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ALL_ACCESS,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
        GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
    },
    System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
};

/// Exclusively creates a regular file with a protected owner/System-only DACL,
/// verifies the effective descriptor, and returns it before any secret write.
pub fn create_owner_only_file(path: &Path) -> io::Result<File> {
    create_owner_only_file_with(path, verify_owner_only_file)
}

/// Opens one existing regular file without following a reparse point, verifies
/// its handle-derived identity and effective owner-only DACL, and returns that
/// same handle for bounded parsing.
#[allow(unsafe_code)]
pub fn open_owner_only_regular_file(path: &Path) -> io::Result<File> {
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `path` is terminated UTF-16. A successful handle is transferred
    // exactly once into `File`; invalid handles are never wrapped.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `CreateFileW` returned one owned handle.
    let file = unsafe { File::from_raw_handle(handle) };
    verify_regular_file_handle(&file)?;
    verify_owner_only_file(&file)?;
    Ok(file)
}

fn create_owner_only_file_with(
    path: &Path,
    verify: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<File> {
    let file = create_owner_only_file_unverified(path)?;
    if let Err(error) = verify(&file) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

#[allow(unsafe_code)]
fn create_owner_only_file_unverified(path: &Path) -> io::Result<File> {
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: pointers reference terminated UTF-16 and initialized output
    // storage. Windows owns `descriptor` until paired `LocalFree` below.
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
        let handle = CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        let error = io::Error::last_os_error();
        LocalFree(descriptor);
        if handle == INVALID_HANDLE_VALUE {
            Err(error)
        } else {
            Ok(File::from_raw_handle(handle))
        }
    }
}

/// Confirms the effective DACL is protected and contains exactly full-control
/// allow entries for Owner Rights and Local System.
#[allow(unsafe_code)]
pub fn verify_owner_only_file(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: `file` supplies a live kernel handle; output pointers remain live
    // until the descriptor is released with `LocalFree`.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let result = verify_descriptor(descriptor, dacl);
    // SAFETY: `descriptor` came from successful `GetSecurityInfo`.
    unsafe { LocalFree(descriptor) };
    result
}

#[allow(unsafe_code)]
fn verify_regular_file_handle(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live handle and output points to initialized,
    // correctly sized storage.
    unsafe {
        if GetFileInformationByHandle(file.as_raw_handle(), &mut information) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(io::Error::other("owner-only handoff is not a regular file"));
    }
    // Reading and all later validation remain on this handle. Volume serial
    // plus file index is the stable identity; querying it also rejects handles
    // whose filesystem cannot provide ordinary file identity.
    let _identity = (
        information.dwVolumeSerialNumber,
        information.nFileIndexHigh,
        information.nFileIndexLow,
    );
    Ok(())
}

#[allow(unsafe_code)]
fn verify_descriptor(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    dacl: *mut windows_sys::Win32::Security::ACL,
) -> io::Result<()> {
    if descriptor.is_null() || dacl.is_null() {
        return Err(io::Error::other("owner-only DACL unavailable"));
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor and DACL were returned together by `GetSecurityInfo`.
    unsafe {
        if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(io::Error::other("owner-only DACL is not protected"));
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        if GetAclInformation(
            dacl,
            (&raw mut info).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        ) == 0
            || info.AceCount != 2
        {
            return Err(io::Error::other("owner-only DACL entry count"));
        }
        let mut owner = false;
        let mut system = false;
        for index in 0..info.AceCount {
            let mut raw_ace = ptr::null_mut();
            if GetAce(dacl, index, &mut raw_ace) == 0 || raw_ace.is_null() {
                return Err(io::Error::last_os_error());
            }
            let ace = &*raw_ace.cast::<ACCESS_ALLOWED_ACE>();
            if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || u32::from(ace.Header.AceFlags) & INHERITED_ACE != 0
                || ace.Mask != FILE_ALL_ACCESS
            {
                return Err(io::Error::other("owner-only DACL entry"));
            }
            let sid = (&raw const ace.SidStart).cast_mut().cast();
            if IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0 {
                owner = true;
            } else if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
                system = true;
            } else {
                return Err(io::Error::other("owner-only DACL principal"));
            }
        }
        if !owner || !system {
            return Err(io::Error::other("owner-only DACL principals"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_path(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "session-chat-native-fs-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn owner_only_file_is_verified_before_use() {
        let path = unique_path("owner-only");
        let file = create_owner_only_file(&path).unwrap();
        verify_owner_only_file(&file).unwrap();
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn verification_failure_leaves_no_file() {
        let path = unique_path("verification-failure");
        let result = create_owner_only_file_with(&path, |_| {
            Err(io::Error::other("injected verification failure"))
        });
        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn reader_rejects_a_file_with_inherited_permissions() {
        let path = unique_path("inherited-permissions");
        fs::write(&path, b"same-length attacker file").unwrap();

        assert!(open_owner_only_regular_file(&path).is_err());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn reader_rejects_a_reparse_point() {
        use std::os::windows::fs::symlink_file;

        let target = unique_path("reparse-target");
        let link = unique_path("reparse-link");
        drop(create_owner_only_file(&target).unwrap());
        symlink_file(&target, &link).unwrap();

        assert!(open_owner_only_regular_file(&link).is_err());

        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }
}

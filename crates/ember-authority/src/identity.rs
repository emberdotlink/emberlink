use std::io;

pub fn executable_digest(path: &std::path::Path) -> io::Result<String> {
    use io::Read as _;
    use sha2::{Digest as _, Sha256};

    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

#[cfg(target_os = "macos")]
pub fn process_pid_version(pid: u32) -> io::Result<u64> {
    crate::macos_process::process_instance(pid)
        .map(|process| process.pid_version())
        .map_err(|error| error.into_io_error())
}

#[cfg(target_os = "macos")]
pub fn observed_process(pid: u32, expected_pid_version: u64) -> io::Result<()> {
    let before = crate::macos_process::reported_process_observation(pid, expected_pid_version)
        .map_err(|error| error.into_io_error())?;
    let after = crate::macos_process::reported_process_observation(pid, expected_pid_version)
        .map_err(|error| error.into_io_error())?;
    if !before.is_same_process_instance(&after, expected_pid_version) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process identity changed",
        ));
    }
    Ok(())
}
#[cfg(target_os = "macos")]
pub fn process_executable_path(
    pid: u32,
    expected_pid_version: u64,
) -> io::Result<std::path::PathBuf> {
    crate::macos_process::reported_process_observation(pid, expected_pid_version)
        .map(|observation| observation.executable_path().to_owned())
        .map_err(|error| error.into_io_error())
}

#[cfg(target_os = "macos")]
pub fn executable_identity(path: &std::path::Path) -> io::Result<String> {
    use std::{ffi::c_void, os::unix::ffi::OsStrExt, ptr};

    type CfTypeRef = *const c_void;
    type CfUrlRef = *const c_void;
    type CfDictionaryRef = *const c_void;
    type CfDataRef = *const c_void;
    type SecStaticCodeRef = *const c_void;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFURLCreateFromFileSystemRepresentation(
            allocator: CfTypeRef,
            bytes: *const u8,
            length: isize,
            is_directory: bool,
        ) -> CfUrlRef;
        fn CFDictionaryGetValue(dictionary: CfDictionaryRef, key: *const c_void) -> *const c_void;
        fn CFDataGetLength(data: CfDataRef) -> isize;
        fn CFDataGetBytePtr(data: CfDataRef) -> *const u8;
        fn CFRelease(value: CfTypeRef);
    }
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecCodeInfoUnique: *const c_void;
        fn SecStaticCodeCreateWithPath(
            path: CfUrlRef,
            flags: u32,
            code: *mut SecStaticCodeRef,
        ) -> i32;
        fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: u32,
            information: *mut CfDictionaryRef,
        ) -> i32;
    }

    let bytes = path.as_os_str().as_bytes();
    let url = unsafe {
        CFURLCreateFromFileSystemRepresentation(
            ptr::null(),
            bytes.as_ptr(),
            bytes
                .len()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path too long"))?,
            false,
        )
    };
    if url.is_null() {
        return Err(io::Error::other("unable to create executable URL"));
    }
    let mut code = ptr::null();
    let create_status = unsafe { SecStaticCodeCreateWithPath(url, 0, &mut code) };
    unsafe { CFRelease(url) };
    if create_status != 0 || code.is_null() {
        return Err(io::Error::other("unable to inspect executable signature"));
    }
    let mut information = ptr::null();
    const SIGNING_INFORMATION: u32 = 1 << 1;
    let copy_status =
        unsafe { SecCodeCopySigningInformation(code, SIGNING_INFORMATION, &mut information) };
    unsafe { CFRelease(code) };
    if copy_status != 0 || information.is_null() {
        return Err(io::Error::other("unable to read executable signature"));
    }
    let data = unsafe { CFDictionaryGetValue(information, kSecCodeInfoUnique) } as CfDataRef;
    if data.is_null() {
        unsafe { CFRelease(information) };
        return Err(io::Error::other("executable has no code identity"));
    }
    let length = unsafe { CFDataGetLength(data) };
    if length != 20 {
        unsafe { CFRelease(information) };
        return Err(io::Error::other("invalid executable code identity"));
    }
    let identity = unsafe { std::slice::from_raw_parts(CFDataGetBytePtr(data), length as usize) };
    let result = format!("cdhash:{}", hex::encode(identity));
    unsafe { CFRelease(information) };
    Ok(result)
}

#[cfg(target_os = "macos")]
pub fn process_executable_identity(pid: u32, expected_pid_version: u64) -> io::Result<String> {
    use std::ffi::c_void;

    unsafe extern "C" {
        fn csops(pid: libc::pid_t, operation: u32, user_address: *mut c_void, size: usize) -> i32;
    }

    observed_process(pid, expected_pid_version)?;
    let mut identity = [0_u8; 20];
    const CS_OPS_CDHASH: u32 = 5;
    let status = unsafe {
        csops(
            pid.try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?,
            CS_OPS_CDHASH,
            identity.as_mut_ptr().cast(),
            identity.len(),
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    observed_process(pid, expected_pid_version)?;
    Ok(format!("cdhash:{}", hex::encode(identity)))
}

#[cfg(target_os = "linux")]
pub fn process_pid_version(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proc stat"))?;
    stat[close + 2..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing process start time"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))
}

#[cfg(target_os = "linux")]
pub fn observed_process(pid: u32, expected_pid_version: u64) -> io::Result<()> {
    let before = process_pid_version(pid)?;
    let link_before = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    let link_after = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    let after = process_pid_version(pid)?;
    if before != expected_pid_version || after != before || link_before != link_after {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process identity changed",
        ));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
pub fn process_executable_path(
    pid: u32,
    expected_pid_version: u64,
) -> io::Result<std::path::PathBuf> {
    if process_pid_version(pid)? != expected_pid_version {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process identity changed",
        ));
    }
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

#[cfg(target_os = "linux")]
fn digest_reader(mut reader: impl io::Read) -> io::Result<String> {
    use sha2::{Digest as _, Sha256};

    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

#[cfg(target_os = "linux")]
pub fn executable_identity(path: &std::path::Path) -> io::Result<String> {
    digest_reader(std::fs::File::open(path)?)
}

#[cfg(target_os = "linux")]
pub fn process_executable_identity(pid: u32, expected_pid_version: u64) -> io::Result<String> {
    if process_pid_version(pid)? != expected_pid_version {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process identity changed",
        ));
    }
    let executable = std::fs::File::open(format!("/proc/{pid}/exe"))?;
    let identity = digest_reader(executable)?;
    if process_pid_version(pid)? != expected_pid_version {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process identity changed",
        ));
    }
    Ok(identity)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_pid_version(_pid: u32) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unsupported host",
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn observed_process(_pid: u32, _expected_pid_version: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unsupported host",
    ))
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_executable_path(
    _pid: u32,
    _expected_pid_version: u64,
) -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unsupported host",
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn executable_identity(_path: &std::path::Path) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unsupported host",
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn process_executable_identity(_pid: u32, _expected_pid_version: u64) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "unsupported host",
    ))
}

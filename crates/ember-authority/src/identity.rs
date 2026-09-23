use std::io;

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

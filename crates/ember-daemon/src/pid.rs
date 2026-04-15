use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PidError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon already running with PID {0}")]
    AlreadyRunning(u32),
    #[error("invalid PID in file: {0}")]
    InvalidPid(String),
}

pub struct PidFile {
    path: PathBuf,
}

impl PidFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(&self) -> Result<(), PidError> {
        if let Some(existing) = self.read()? {
            if is_process_running(existing) {
                return Err(PidError::AlreadyRunning(existing));
            }
            // Stale PID file from a crashed process — remove it before overwriting.
            let _ = fs::remove_file(&self.path);
        }
        let pid = std::process::id();
        fs::write(&self.path, format!("{pid}\n"))?;
        Ok(())
    }

    pub fn read(&self) -> Result<Option<u32>, PidError> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => {
                let trimmed = contents.trim();
                trimmed
                    .parse::<u32>()
                    .map(Some)
                    .map_err(|_| PidError::InvalidPid(trimmed.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PidError::Io(e)),
        }
    }

    pub fn is_running(&self) -> bool {
        match self.read() {
            Ok(Some(pid)) => is_process_running(pid),
            _ => false,
        }
    }

    pub fn remove(&self) -> Result<(), PidError> {
        fs::remove_file(&self.path)?;
        Ok(())
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

fn is_process_running(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_read_matches_current_pid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.pid");
        let pf = PidFile::new(path);
        pf.write().unwrap();
        let read_pid = pf.read().unwrap().expect("should have a PID");
        assert_eq!(read_pid, std::process::id());
        // Suppress Drop removal since file is already gone after the test
        // (Drop will silently fail — that's fine).
    }

    #[test]
    fn is_running_true_for_current_process() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("running.pid");
        let pf = PidFile::new(path);
        pf.write().unwrap();
        assert!(pf.is_running());
    }

    #[test]
    fn remove_makes_read_return_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("remove.pid");
        // Wrap in a block so Drop doesn't fight our explicit remove.
        {
            let pf = PidFile::new(path.clone());
            pf.write().unwrap();
            pf.remove().unwrap();
            // Inhibit the Drop removal (file is gone) by using std::mem::forget.
            std::mem::forget(pf);
        }
        let pf2 = PidFile::new(path);
        assert!(pf2.read().unwrap().is_none());
        std::mem::forget(pf2);
    }

    #[test]
    fn stale_pid_file_is_overwritten() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("stale.pid");
        // Write a PID that cannot be running (PID 0 is never a user process).
        // Use a large number that's almost certainly not running.
        let stale_pid: u32 = 9_999_999;
        fs::write(&path, format!("{stale_pid}\n")).unwrap();
        let pf = PidFile::new(path);
        // write() should succeed because the stale PID is not running.
        pf.write().unwrap();
        let read_pid = pf.read().unwrap().unwrap();
        assert_eq!(read_pid, std::process::id());
    }

    #[test]
    fn already_running_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("alive.pid");
        // Write the current PID manually — simulates a live daemon.
        fs::write(&path, format!("{}\n", std::process::id())).unwrap();
        let pf = PidFile::new(path);
        match pf.write() {
            Err(PidError::AlreadyRunning(pid)) => assert_eq!(pid, std::process::id()),
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
        std::mem::forget(pf);
    }

    #[test]
    fn invalid_content_returns_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.pid");
        fs::write(&path, "not-a-number\n").unwrap();
        let pf = PidFile::new(path);
        match pf.read() {
            Err(PidError::InvalidPid(s)) => assert_eq!(s, "not-a-number"),
            other => panic!("expected InvalidPid, got {other:?}"),
        }
        std::mem::forget(pf);
    }
}

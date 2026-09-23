use crate::model::Refusal;
use std::{
    fs,
    os::unix::{
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    time::{Duration, Instant},
};

/// Owns the mechanics of one Session-private endpoint and reviewed child.
/// Authority decisions remain in `AuthorityControl` and
/// `ExecutionBindingAuthority`.
pub struct SessionSupervisor {
    endpoint: PathBuf,
    listener: UnixListener,
    child: Option<Child>,
}

impl SessionSupervisor {
    pub fn bind(endpoint: PathBuf) -> Result<Self, Refusal> {
        let parent = endpoint
            .parent()
            .ok_or_else(|| Refusal::new("session_endpoint_failed"))?;
        fs::create_dir_all(parent).map_err(|_| Refusal::new("state_unavailable"))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| Refusal::new("state_unavailable"))?;
        let listener =
            UnixListener::bind(&endpoint).map_err(|_| Refusal::new("session_endpoint_failed"))?;
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600))
            .map_err(|_| Refusal::new("session_endpoint_failed"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Refusal::new("session_endpoint_failed"))?;
        Ok(Self {
            endpoint,
            listener,
            child: None,
        })
    }

    pub fn launch(&mut self, command: &mut Command) -> Result<u32, Refusal> {
        if self.child.is_some() {
            return Err(Refusal::new("session_launch_failed"));
        }
        let child = command
            .spawn()
            .map_err(|_| Refusal::new("session_launch_failed"))?;
        let pid = child.id();
        self.child = Some(child);
        Ok(pid)
    }

    pub fn child_id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    pub fn accept_before(&self, deadline: Instant) -> Result<UnixStream, Refusal> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|_| Refusal::new("transport_failed"))?;
                    return Ok(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(Refusal::new("session_launch_failed"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(Refusal::new("session_endpoint_failed")),
            }
        }
    }

    pub fn wait_with_output(&mut self) -> Result<Output, Refusal> {
        self.child
            .take()
            .ok_or_else(|| Refusal::new("session_launch_failed"))?
            .wait_with_output()
            .map_err(|_| Refusal::new("session_launch_failed"))
    }
}

impl Drop for SessionSupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if Path::new(&self.endpoint).exists() {
            let _ = fs::remove_file(&self.endpoint);
        }
    }
}

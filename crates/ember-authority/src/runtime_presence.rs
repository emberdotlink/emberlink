use std::os::fd::{AsRawFd, RawFd};

use crate::model::{Refusal, SessionRecord, SessionState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedProcess {
    pub uid: u32,
    pub pid: u32,
    pub pid_version: u64,
}

pub struct ExecutionBindingAuthority;

impl ExecutionBindingAuthority {
    pub fn authenticate_fd(fd: &impl AsRawFd) -> Result<AuthenticatedProcess, Refusal> {
        read_peer(fd.as_raw_fd())
    }

    pub fn revalidate(
        session: &SessionRecord,
        observed: AuthenticatedProcess,
    ) -> Result<(), Refusal> {
        if session.state != SessionState::Active
            || session.expected_uid != observed.uid
            || session.expected_pid != Some(observed.pid)
            || session.expected_pid_version != Some(observed.pid_version)
        {
            return Err(Refusal::new("session_binding_mismatch"));
        }
        crate::identity::observed_process(observed.pid, observed.pid_version)
            .map_err(|_| Refusal::new("process_identity_unavailable"))?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn read_peer(fd: RawFd) -> Result<AuthenticatedProcess, Refusal> {
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    let mut token = [0_u32; 8];
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of_val(&token) {
        return Err(Refusal::new("process_identity_unavailable"));
    }
    Ok(AuthenticatedProcess {
        uid: token[1],
        pid: token[5],
        pid_version: token[7] as u64,
    })
}

#[cfg(target_os = "linux")]
fn read_peer(fd: RawFd) -> Result<AuthenticatedProcess, Refusal> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || cred.pid <= 0 {
        return Err(Refusal::new("process_identity_unavailable"));
    }
    let pid_version = crate::identity::process_pid_version(cred.pid as u32)
        .map_err(|_| Refusal::new("process_identity_unavailable"))?;
    Ok(AuthenticatedProcess {
        uid: cred.uid,
        pid: cred.pid as u32,
        pid_version,
    })
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_peer(_fd: RawFd) -> Result<AuthenticatedProcess, Refusal> {
    Err(Refusal::new("process_identity_unavailable"))
}

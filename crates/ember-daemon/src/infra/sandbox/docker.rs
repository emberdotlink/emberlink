use std::fmt;
use std::io;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(not(test))]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub(super) enum DockerCliError {
    Spawn {
        args: Vec<String>,
        source: io::Error,
    },
    Wait {
        args: Vec<String>,
        source: io::Error,
    },
    Timeout {
        args: Vec<String>,
        timeout: Duration,
    },
}

impl fmt::Display for DockerCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { args, source } => {
                write!(f, "spawn `{}`: {source}", command_label(args))
            }
            Self::Wait { args, source } => {
                write!(f, "wait for `{}`: {source}", command_label(args))
            }
            Self::Timeout { args, timeout } => write!(
                f,
                "`{}` timed out after {:.1}s",
                command_label(args),
                timeout.as_secs_f32()
            ),
        }
    }
}

impl std::error::Error for DockerCliError {}

pub(super) fn output<I, S>(args: I) -> Result<Output, DockerCliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string())
        .collect();
    let mut child = Command::new("docker")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| DockerCliError::Spawn {
            args: args.clone(),
            source,
        })?;

    let timeout = command_timeout();
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|source| DockerCliError::Wait { args, source });
            }
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(DockerCliError::Timeout { args, timeout });
            }
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(source) => {
                return Err(DockerCliError::Wait { args, source });
            }
        }
    }
}

#[cfg(test)]
pub(super) fn available_with_local_image(image: &str) -> bool {
    output(["info"])
        .map(|output| output.status.success())
        .unwrap_or(false)
        && output(["image", "inspect", image])
            .map(|output| output.status.success())
            .unwrap_or(false)
}

fn command_timeout() -> Duration {
    std::env::var("EMBER_DAEMON_DOCKER_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|millis| *millis > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_TIMEOUT)
}

fn command_label(args: &[String]) -> String {
    if args.is_empty() {
        "docker".to_string()
    } else {
        format!("docker {}", args.join(" "))
    }
}

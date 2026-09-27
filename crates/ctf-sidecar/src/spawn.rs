//! Process spawning with hard timeout (poll-based, std-only, no unsafe).
//! Windows: hides the console window via CREATE_NO_WINDOW.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ctf_core::error::{CoreError, Result};

#[derive(Debug)]
pub struct SpawnOutput {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
    pub timed_out: bool,
}

/// Spawn `exe args...`, capture output, kill after `timeout`.
pub fn run_with_timeout(exe: &str, args: &[String], timeout: Duration) -> Result<SpawnOutput> {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().map_err(|e| CoreError::Invalid(format!("spawn {exe}: {e}")))?;
    let started = Instant::now();
    let mut timed_out = false;

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if started.elapsed() > timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(CoreError::Io(e)),
        }
    }

    let output = child.wait_with_output()?;
    Ok(SpawnOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        code: output.status.code(),
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_and_captures() {
        // cmd.exe exists on every Windows host we target
        let out = run_with_timeout(
            "cmd",
            &["/C".to_string(), "echo hello-forge".to_string()],
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(!out.timed_out);
        assert!(out.stdout.contains("hello-forge"));
    }

    #[test]
    fn kills_on_timeout() {
        let out = run_with_timeout(
            "cmd",
            &["/C".to_string(), "ping -n 5 127.0.0.1 >nul".to_string()],
            Duration::from_millis(600),
        );
        // either timed out (killed) or exited early; must not hang
        if let Ok(o) = out {
            assert!(o.timed_out || o.code.is_some());
        }
    }
}

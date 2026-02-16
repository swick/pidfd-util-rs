// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};

fn spawn_and_status(cmd: &mut Command) -> io::Result<ExitStatus> {
    let child = cmd.spawn()?;
    let pidfd = PidFd::from_pid(child.id().try_into().unwrap())?;
    pidfd.wait()
}

#[test]
fn test_status() -> io::Result<()> {
    let status = spawn_and_status(&mut Command::new("/bin/true"))?;
    assert_eq!(status.code(), Some(0));
    assert_eq!(status.signal(), None);
    let status = spawn_and_status(&mut Command::new("/bin/false"))?;
    assert_eq!(status.code(), Some(1));
    assert_eq!(status.signal(), None);
    let status = spawn_and_status(Command::new("/bin/sh").arg("-c").arg("kill -9 $$"))?;
    assert_eq!(status.code(), None);
    assert_eq!(status.signal(), Some(9));
    Ok(())
}

#[test]
fn test_wait_twice() -> io::Result<()> {
    let child = Command::new("/bin/true").spawn()?;
    let pidfd = PidFd::from_pid(child.id().try_into().unwrap())?;
    let status = pidfd.wait()?;
    assert!(status.success());
    let status = pidfd.wait()?;
    assert!(status.success());
    Ok(())
}

#[cfg(feature = "async")]
async fn async_spawn_and_status(cmd: &mut Command) -> io::Result<ExitStatus> {
    let child = cmd.spawn()?;
    let pidfd: AsyncPidFd = PidFd::from_pid(child.id().try_into().unwrap())?.try_into()?;
    pidfd.wait().await
}

#[test]
#[cfg(feature = "async")]
fn test_async() -> io::Result<()> {
    use futures_lite::future;
    future::block_on(async {
        let (status1, status2) = future::try_zip(
            async_spawn_and_status(&mut Command::new("/bin/true")),
            async_spawn_and_status(&mut Command::new("/bin/false")),
        )
        .await?;
        assert_eq!(status1.code(), Some(0));
        assert_eq!(status2.code(), Some(1));
        Ok(())
    })
}

#[test]
#[cfg(feature = "async")]
fn test_async_concurrent() -> std::io::Result<()> {
    use futures_lite::future::{self, FutureExt};
    future::block_on(async {
        let status = async_spawn_and_status(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("read line")
                .stdin(std::process::Stdio::piped()),
        )
        .or(async_spawn_and_status(&mut Command::new("/bin/false")))
        .await?;
        assert_eq!(status.code(), Some(1));
        Ok(())
    })
}

#[test]
#[cfg(feature = "async")]
fn test_async_wait_twice() -> std::io::Result<()> {
    futures_lite::future::block_on(async {
        let child = Command::new("/bin/true").spawn()?;
        let pidfd: AsyncPidFd = PidFd::from_pid(child.id() as libc::pid_t)?.try_into()?;
        let status = pidfd.wait().await?;
        assert!(status.success());
        let status = pidfd.wait().await?;
        assert!(status.success());
        Ok(())
    })
}

#[test]
fn test_pid() {
    use std::process::id;

    let pidfd = PidFd::from_pid(id().try_into().unwrap()).unwrap();
    match pidfd.get_pid() {
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
        Ok(pid) => assert_eq!(pid, id() as i32),
    }
}

#[test]
fn test_ppid() {
    use std::os::unix::process::parent_id;
    use std::process::id;

    let pidfd = PidFd::from_pid(id().try_into().unwrap()).unwrap();
    match pidfd.get_ppid() {
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
        Ok(pid) => assert_eq!(pid, parent_id() as i32),
    }
}

#[test]
fn test_access_proc() {
    #[allow(clippy::zombie_processes)]
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 1000")
        .spawn()
        .unwrap();
    let pidfd = PidFd::from_pid(child.id().try_into().unwrap()).unwrap();
    let result = pidfd.access_proc(|| 42);
    pidfd.kill().unwrap();
    pidfd.wait().unwrap();
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_access_proc_fail() {
    #[allow(clippy::zombie_processes)]
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 1000")
        .spawn()
        .unwrap();
    let pidfd = PidFd::from_pid(child.id().try_into().unwrap()).unwrap();
    let result = pidfd.access_proc(|| {
        pidfd.kill().unwrap();
        pidfd.wait().unwrap();
        42
    });
    result.unwrap_err();
}

#[test]
fn test_id() {
    use std::process::id;

    let pidfd1 = PidFd::from_pid(id().try_into().unwrap()).unwrap();
    let pidfd2 = PidFd::from_pid(id().try_into().unwrap()).unwrap();
    assert_eq!(pidfd1.get_id().unwrap(), pidfd2.get_id().unwrap());

    let mut child = Command::new("/bin/true").spawn().unwrap();
    let pidfd3 = PidFd::from_pid(child.id().try_into().unwrap()).unwrap();
    assert_ne!(pidfd1.get_id().unwrap(), pidfd3.get_id().unwrap());
    child.wait().unwrap();
}

#[test]
fn test_creds() {
    use nix::unistd::{Gid, Uid};
    use std::process::id;

    let pidfd = PidFd::from_pid(id().try_into().unwrap()).unwrap();
    let creds = pidfd.get_creds().unwrap();
    assert_eq!(creds.ruid, Uid::current().as_raw());
    assert_eq!(creds.euid, Uid::effective().as_raw());
    assert_eq!(creds.rgid, Gid::current().as_raw());
    assert_eq!(creds.egid, Gid::effective().as_raw());
}
#[test]
fn test_get_namespace() {
    // FIXME, how to test? probably needs some user namespace magic
}

#[test]
fn test_set_namespace() {
    // FIXME, how to test? probably needs some user namespace magic
}

#[test]
fn test_get_remote_fd() {
    // FIXME, how to test? needs ptrace permission. probably need to do some user namespace thing...
}

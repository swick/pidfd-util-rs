// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

// FIXME: make async a feature
// FIXME: add docs

#![cfg_attr(feature = "nightly", feature(linux_pidfd))]

mod lowlevel;

use async_io::Async;
use std::os::fd::OwnedFd;
use std::{io, process::ExitStatus};

#[cfg(not(feature = "nightly"))]
mod pidfd_impl {
    use super::lowlevel::{pidfd_send_signal, pidfd_try_wait, pidfd_wait};
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::process::ExitStatus;

    pub struct PidFd(OwnedFd);

    impl PidFd {
        pub fn kill(&self) -> io::Result<()> {
            pidfd_send_signal(self, libc::SIGKILL)
        }

        pub fn wait(&self) -> io::Result<ExitStatus> {
            pidfd_wait(self)
        }

        pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
            pidfd_try_wait(self)
        }
    }

    impl AsRawFd for PidFd {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    impl FromRawFd for PidFd {
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            // SAFETY:
            // The caller must ensure that fd is a valid Pidfd.
            unsafe { Self(OwnedFd::from_raw_fd(fd)) }
        }
    }

    impl IntoRawFd for PidFd {
        fn into_raw_fd(self) -> RawFd {
            self.0.into_raw_fd()
        }
    }

    impl AsFd for PidFd {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    impl From<OwnedFd> for PidFd {
        fn from(fd: OwnedFd) -> Self {
            Self(fd)
        }
    }

    impl From<PidFd> for OwnedFd {
        fn from(pid_fd: PidFd) -> Self {
            pid_fd.0
        }
    }
}

#[cfg(not(feature = "nightly"))]
pub use pidfd_impl::*;
#[cfg(feature = "nightly")]
pub use std::os::linux::process::PidFd;

pub use lowlevel::{PidfdCreds, PidfdGetNamespace};
use lowlevel::{
    pidfd_get_cgroupid, pidfd_get_creds, pidfd_get_inode_id, pidfd_get_namespace, pidfd_get_pid,
    pidfd_get_ppid, pidfd_getfd, pidfd_open, pidfd_send_signal,
};
pub use nix::sched::CloneFlags;

pub trait PidFdExt {
    fn from_self() -> io::Result<PidFd>;

    fn from_pid(pid: i32) -> io::Result<PidFd>;

    fn get_pid(&self) -> io::Result<i32>;

    fn get_ppid(&self) -> io::Result<i32>;

    fn get_id(&self) -> io::Result<u64>;

    fn get_creds(&self) -> io::Result<PidfdCreds>;

    fn get_cgroupid(&self) -> io::Result<u64>;

    fn get_namespace(&self, ns: &PidfdGetNamespace) -> io::Result<OwnedFd>;

    fn access_proc<R, F: FnOnce() -> R>(&self, func: F) -> io::Result<R>;

    fn send_signal(&self, signal: i32) -> io::Result<()>;

    fn set_namespace(&self, ns: CloneFlags) -> io::Result<()>;

    fn get_remote_fd(&self, target_fd: i32) -> io::Result<OwnedFd>;
}

impl PidFdExt for PidFd {
    fn from_self() -> io::Result<PidFd> {
        Self::from_pid(std::process::id().try_into().unwrap())
    }

    fn from_pid(pid: i32) -> io::Result<PidFd> {
        pidfd_open(pid as libc::pid_t).map(PidFd::from)
    }

    fn get_pid(&self) -> io::Result<i32> {
        pidfd_get_pid(self)
    }

    fn get_ppid(&self) -> io::Result<i32> {
        pidfd_get_ppid(self)
    }

    fn get_id(&self) -> io::Result<u64> {
        pidfd_get_inode_id(self)
    }

    fn get_creds(&self) -> io::Result<PidfdCreds> {
        pidfd_get_creds(self)
    }

    fn get_cgroupid(&self) -> io::Result<u64> {
        pidfd_get_cgroupid(self)
    }

    fn get_namespace(&self, ns: &PidfdGetNamespace) -> io::Result<OwnedFd> {
        pidfd_get_namespace(self, ns)
    }

    fn access_proc<R, F: FnOnce() -> R>(&self, func: F) -> io::Result<R> {
        let pid = self.get_pid()?;
        let result = func();
        let pid_after = self.get_pid()?;

        if pid != pid_after {
            return Err(io::ErrorKind::NotFound.into());
        }

        Ok(result)
    }

    fn send_signal(&self, signal: i32) -> io::Result<()> {
        pidfd_send_signal(self, signal)
    }

    fn set_namespace(&self, ns: CloneFlags) -> io::Result<()> {
        Ok(nix::sched::setns(self, ns)?)
    }

    fn get_remote_fd(&self, target_fd: i32) -> io::Result<OwnedFd> {
        pidfd_getfd(self, target_fd)
    }
}

impl TryFrom<PidFd> for AsyncPidFd {
    type Error = io::Error;

    fn try_from(pifd: PidFd) -> Result<Self, io::Error> {
        Ok(Self(Async::new(pifd)?))
    }
}

pub struct AsyncPidFd(Async<PidFd>);

impl AsyncPidFd {
    pub async fn wait(&self) -> io::Result<ExitStatus> {
        self.0.readable().await?;
        self.0.get_ref().wait()
    }
}

#[cfg(test)]
mod tests {
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

    fn assert_echild(ret: io::Result<ExitStatus>) {
        if let Err(e) = ret {
            assert_eq!(e.raw_os_error(), Some(libc::ECHILD));
        } else {
            panic!("Expected an error!");
        }
    }

    #[test]
    fn test_wait_twice() -> io::Result<()> {
        let child = Command::new("/bin/true").spawn()?;
        let pidfd = PidFd::from_pid(child.id().try_into().unwrap())?;
        let status = pidfd.wait()?;
        assert!(status.success());
        let ret = pidfd.wait();
        assert_echild(ret);
        Ok(())
    }

    async fn async_spawn_and_status(cmd: &mut Command) -> io::Result<ExitStatus> {
        let child = cmd.spawn()?;
        let pidfd: AsyncPidFd = PidFd::from_pid(child.id().try_into().unwrap())?.try_into()?;
        pidfd.wait().await
    }

    #[test]
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
    fn test_async_wait_twice() -> std::io::Result<()> {
        futures_lite::future::block_on(async {
            let child = Command::new("/bin/true").spawn()?;
            let pidfd: AsyncPidFd = PidFd::from_pid(child.id() as libc::pid_t)?.try_into()?;
            let status = pidfd.wait().await?;
            assert!(status.success());
            let ret = pidfd.wait().await;
            assert_echild(ret);
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
}

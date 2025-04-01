#![cfg_attr(feature = "nightly", feature(linux_pidfd))]

use async_io::Async;
use std::{
    io,
    os::fd::{FromRawFd, OwnedFd},
    process::ExitStatus,
};

trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

#[cfg(feature = "nightly")]
pub use std::os::linux::process::PidFd;

#[cfg(not(feature = "nightly"))]
mod imported_nightly_impl {
    use super::cvt;
    use std::{
        io,
        os::{
            fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
            unix::process::ExitStatusExt,
        },
        process::ExitStatus,
    };

    fn from_waitid_siginfo(siginfo: libc::siginfo_t) -> ExitStatus {
        let status = unsafe { siginfo.si_status() };

        match siginfo.si_code {
            libc::CLD_EXITED => ExitStatus::from_raw((status & 0xff) << 8),
            libc::CLD_KILLED => ExitStatus::from_raw(status),
            libc::CLD_DUMPED => ExitStatus::from_raw(status | 0x80),
            libc::CLD_CONTINUED => ExitStatus::from_raw(0xffff),
            libc::CLD_STOPPED | libc::CLD_TRAPPED => {
                ExitStatus::from_raw(((status & 0xff) << 8) | 0x7f)
            }
            _ => unreachable!("waitid() should only return the above codes"),
        }
    }

    pub struct PidFd(OwnedFd);

    impl PidFd {
        pub fn kill(&self) -> io::Result<()> {
            cvt(unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.0.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<()>(),
                    0,
                )
            })
            .map(drop)
        }

        pub fn wait(&self) -> io::Result<ExitStatus> {
            let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
            cvt(unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.0.as_raw_fd() as u32,
                    &mut siginfo,
                    libc::WEXITED,
                )
            })?;
            Ok(from_waitid_siginfo(siginfo))
        }

        pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
            let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };

            cvt(unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.0.as_raw_fd() as u32,
                    &mut siginfo,
                    libc::WEXITED | libc::WNOHANG,
                )
            })?;
            if unsafe { siginfo.si_pid() } == 0 {
                Ok(None)
            } else {
                Ok(Some(from_waitid_siginfo(siginfo)))
            }
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
pub use imported_nightly_impl::*;

pub trait PidFdExt {
    fn from_pid(pid: libc::pid_t) -> io::Result<PidFd>;

    // / TODO:
    // / https://github.com/systemd/systemd/blob/main/src/basic/pidfd-util.c
    // / pidfd_get_pid
    // / pidfd_get_ppid
    // / pidfd_verify_pid (or rather something to look up /proc things in a callback)
    // / pidfd_get_uid
    // / pidfd_get_cgroupid
    // / pidfd_get_namespace?
    // / pidfd_get_inode_id? This returns a unique id for the process which is not racy (statx, stx_ino;) is pidfd different process?
    // / ^ equal
    // / https://codeberg.org/PatchMixolydic/pidfd_getfd/src/branch/main/src/linux.rs
    // / pidfd_getfd ? ptrace thing, probably not useful.
    // / https://github.com/MaxVerevkin/async-pidfd/blob/main/src/lib.rs
    // / async
    // / https://www.corsix.org/content/what-is-a-pidfd
    // / send_signal (impl for kill)
    // / setns
    // /
}

impl PidFdExt for PidFd {
    fn from_pid(pid: libc::pid_t) -> io::Result<PidFd> {
        let pidfd: std::result::Result<OwnedFd, io::Error> = unsafe {
            let fd = cvt(libc::syscall(libc::SYS_pidfd_open, pid, 0))?;
            Ok(OwnedFd::from_raw_fd(fd as libc::c_int))
        };

        pidfd.map(PidFd::from)
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
        let pidfd = PidFd::from_pid(child.id() as libc::pid_t)?;
        pidfd.wait()
    }

    #[test]
    fn status() -> io::Result<()> {
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
        let pidfd = PidFd::from_pid(child.id() as libc::pid_t)?;
        let status = pidfd.wait()?;
        assert!(status.success());
        let ret = pidfd.wait();
        assert_echild(ret);
        Ok(())
    }

    async fn async_spawn_and_status(cmd: &mut Command) -> io::Result<ExitStatus> {
        let child = cmd.spawn()?;
        let pidfd: AsyncPidFd = PidFd::from_pid(child.id() as libc::pid_t)?.try_into()?;
        Ok(pidfd.wait().await?)
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
    fn it_works() {
        let _pidfd = PidFd::from_pid(std::process::id().try_into().unwrap()).unwrap();

        //pidfd.kill().unwrap();
    }
}

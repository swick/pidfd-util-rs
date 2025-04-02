#![cfg_attr(feature = "nightly", feature(linux_pidfd))]

/*
 * FIXME: make async a feature
 */
use async_io::Async;
use std::{io, process::ExitStatus};

mod lowlevel {
    use nix::ioctl_readwrite;
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    #[cfg(not(feature = "nightly"))]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(not(feature = "nightly"))]
    use std::process::ExitStatus;

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

    fn ioctl_unsupported(e: nix::Error) -> nix::Error {
        match e {
            nix::Error::EOPNOTSUPP
            | nix::Error::ENOTTY
            | nix::Error::ENOSYS
            | nix::Error::EAFNOSUPPORT
            | nix::Error::EPFNOSUPPORT
            | nix::Error::EPROTONOSUPPORT
            | nix::Error::ESOCKTNOSUPPORT
            | nix::Error::ENOPROTOOPT => nix::Error::EOPNOTSUPP,
            e => e,
        }
    }

    const PIDFS_IOCTL_MAGIC: u8 = 0xFF;
    const PIDFS_IOCTL_GET_INFO: u8 = 11;

    #[non_exhaustive]
    struct PidfdInfoFlags;

    impl PidfdInfoFlags {
        /* Always returned, even if not requested */
        pub const PID: u64 = 1 << 0;
        /* Always returned, even if not requested */
        #[allow(dead_code)]
        pub const CREDS: u64 = 1 << 1;
        /* Always returned if available, even if not requested */
        #[allow(dead_code)]
        pub const CGROUPID: u64 = 1 << 2;
        /* Only returned if requested. */
        #[allow(dead_code)]
        pub const EXIT: u64 = 1 << 3;
    }

    #[derive(Debug, Default)]
    #[repr(C)]
    struct PidfdInfo {
        mask: u64,
        cgroupid: u64,
        pid: u32,
        tgid: u32,
        ppid: u32,
        ruid: u32,
        rgid: u32,
        euid: u32,
        egid: u32,
        suid: u32,
        sgid: u32,
        fsuid: u32,
        fsgid: u32,
        exit_code: i32,
    }

    ioctl_readwrite!(
        pidfd_get_info_ioctl,
        PIDFS_IOCTL_MAGIC,
        PIDFS_IOCTL_GET_INFO,
        PidfdInfo
    );

    fn pidfd_get_info(pidfd: RawFd, flags: u64) -> Result<PidfdInfo, nix::Error> {
        use std::sync::atomic::AtomicU8;
        use std::sync::atomic::Ordering;

        assert_eq!(64, std::mem::size_of::<PidfdInfo>());

        static PIDFD_GET_INFO_SUPPORTED: AtomicU8 = AtomicU8::new(0);
        const UNKNOWN: u8 = 0;
        const YES: u8 = 1;
        const NO: u8 = 2;

        let mut supported = PIDFD_GET_INFO_SUPPORTED.load(Ordering::Relaxed);
        if supported == NO {
            return Err(nix::Error::EOPNOTSUPP);
        }

        let mut info = PidfdInfo::default();
        info.mask = flags;

        let r = unsafe { pidfd_get_info_ioctl(pidfd, &mut info) }.map_err(ioctl_unsupported);

        if supported == UNKNOWN {
            match r {
                Err(nix::Error::EOPNOTSUPP) => supported = NO,
                _ => supported = YES,
            }
            PIDFD_GET_INFO_SUPPORTED.store(supported, Ordering::Relaxed);
        }

        r?;

        assert!(info.mask & flags == flags);
        Ok(info)
    }

    pub fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
        unsafe {
            let fd = cvt(libc::syscall(libc::SYS_pidfd_open, pid, 0))?;
            Ok(OwnedFd::from_raw_fd(fd as libc::c_int))
        }
    }

    #[cfg(not(feature = "nightly"))]
    pub fn pidfd_kill(pidfd: RawFd) -> io::Result<()> {
        cvt(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                libc::SIGKILL,
                std::ptr::null::<()>(),
                0,
            )
        })
        .map(drop)
    }

    #[cfg(not(feature = "nightly"))]
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

    #[cfg(not(feature = "nightly"))]
    pub fn pidfd_wait(pidfd: RawFd) -> io::Result<ExitStatus> {
        let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };
        cvt(unsafe { libc::waitid(libc::P_PIDFD, pidfd as u32, &mut siginfo, libc::WEXITED) })?;
        Ok(from_waitid_siginfo(siginfo))
    }

    #[cfg(not(feature = "nightly"))]
    pub fn pidfd_try_wait(pidfd: RawFd) -> io::Result<Option<ExitStatus>> {
        let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };

        cvt(unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pidfd as u32,
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

    fn pidfd_get_pid_fdinfo(pidfd: RawFd) -> io::Result<i32> {
        use std::fs::read_to_string;

        let fdinfo = read_to_string(format!("/proc/self/fdinfo/{pidfd}"))?;
        let pidline = fdinfo
            .split('\n')
            .find(|s| s.starts_with("Pid:"))
            .ok_or(io::ErrorKind::Unsupported)?;
        Ok(pidline
            .split('\t')
            .next_back()
            .ok_or(io::ErrorKind::Unsupported)?
            .parse::<i32>()
            .map_err(|_| io::ErrorKind::Unsupported)?)
    }

    pub fn pidfd_get_pid(pidfd: RawFd) -> io::Result<i32> {
        match pidfd_get_info(pidfd, PidfdInfoFlags::PID) {
            Ok(info) => Ok(info.pid as i32),
            Err(nix::Error::EOPNOTSUPP) => pidfd_get_pid_fdinfo(pidfd),
            Err(e) => return Err(e.into()),
        }
    }

    pub fn pidfd_get_ppid(pidfd: RawFd) -> io::Result<i32> {
        Ok(pidfd_get_info(pidfd, PidfdInfoFlags::PID)
            .map(|info| info.ppid as i32)?)
    }
}

#[cfg(not(feature = "nightly"))]
mod pidfd_impl {
    use super::lowlevel::{pidfd_kill, pidfd_try_wait, pidfd_wait};
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::process::ExitStatus;

    pub struct PidFd(OwnedFd);

    impl PidFd {
        pub fn kill(&self) -> io::Result<()> {
            pidfd_kill(self.0.as_raw_fd())
        }

        pub fn wait(&self) -> io::Result<ExitStatus> {
            pidfd_wait(self.0.as_raw_fd())
        }

        pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
            pidfd_try_wait(self.0.as_raw_fd())
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
pub use pidfd_impl::*;

#[cfg(feature = "nightly")]
pub use std::os::linux::process::PidFd;

use lowlevel::{pidfd_open, pidfd_get_pid, pidfd_get_ppid};

pub trait PidFdExt {
    fn from_pid(pid: i32) -> io::Result<PidFd>;

    fn get_pid(&self) -> io::Result<i32>;

    fn get_ppid(&self) -> io::Result<i32>;

    fn access_proc<R, F: FnOnce() -> R>(&self, func: F) -> io::Result<R>;

    // / TODO:
    // / https://github.com/systemd/systemd/blob/main/src/basic/pidfd-util.c
    // / pidfd_verify_pid (or rather something to look up /proc things in a callback)
    // / pidfd_get_uid
    // / pidfd_get_cgroupid
    // / pidfd_get_namespace?
    // / pidfd_get_inode_id? This returns a unique id for the process which is not racy (statx, stx_ino;) is pidfd different process?
    // / ^ equal
    // / https://codeberg.org/PatchMixolydic/pidfd_getfd/src/branch/main/src/linux.rs
    // / pidfd_getfd ? ptrace thing, probably not useful.
    // / https://www.corsix.org/content/what-is-a-pidfd
    // / send_signal (impl for kill)
    // / setns
    //
    // verify pid as pidfd (systemd)
    //
    // /
}

impl PidFdExt for PidFd {
    fn from_pid(pid: i32) -> io::Result<PidFd> {
        pidfd_open(pid as libc::pid_t).map(PidFd::from)
    }

    fn get_pid(&self) -> io::Result<i32> {
        use std::os::fd::AsRawFd;

        pidfd_get_pid(self.as_raw_fd())
    }

    fn get_ppid(&self) -> io::Result<i32> {
        use std::os::fd::AsRawFd;

        pidfd_get_ppid(self.as_raw_fd())
    }

    fn access_proc<R, F: FnOnce() -> R>(&self, func: F) -> io::Result<R> {
        let pid = self.get_pid()?;
        let result = func();
        let pid_after = self.get_pid()?;

        if pid != pid_after { return Err(io::ErrorKind::NotFound.into()); }

        return Ok(result);
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
        use std::process::id;
        use std::os::unix::process::parent_id;

        let pidfd = PidFd::from_pid(id().try_into().unwrap()).unwrap();
        match pidfd.get_ppid() {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
            Ok(pid) => assert_eq!(pid, parent_id() as i32),
        }
    }

    #[test]
    fn test_access_proc() {
        let child = Command::new("/bin/sh").arg("-c").arg("sleep 1000").spawn().unwrap();
        let pidfd = PidFd::from_pid(child.id().try_into().unwrap()).unwrap();
        let result = pidfd.access_proc(|| {
            return 42;
        });
        pidfd.kill().unwrap();
        pidfd.wait().unwrap();
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_access_proc_fail() {
        let child = Command::new("/bin/sh").arg("-c").arg("sleep 1000").spawn().unwrap();
        let pidfd = PidFd::from_pid(child.id().try_into().unwrap()).unwrap();
        let result = pidfd.access_proc(|| {
            pidfd.kill().unwrap();
            pidfd.wait().unwrap();
            return 42;
        });
        result.unwrap_err();
    }
}

#![cfg_attr(feature = "nightly", feature(linux_pidfd))]

/*
 * FIXME: make async a feature
 */
use async_io::Async;
use std::os::fd::{AsRawFd, OwnedFd};
use std::{io, process::ExitStatus};

mod lowlevel {
    use nix::{ioctl_readwrite, request_code_none};
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

    const PIDFS_IOCTL_GET_CGROUP_NAMESPACE: u8 = 1;
    const PIDFS_IOCTL_GET_IPC_NAMESPACE: u8 = 2;
    const PIDFS_IOCTL_GET_MNT_NAMESPACE: u8 = 3;
    const PIDFS_IOCTL_GET_NET_NAMESPACE: u8 = 4;
    const PIDFS_IOCTL_GET_PID_NAMESPACE: u8 = 5;
    const PIDFS_IOCTL_GET_PID_FOR_CHILDREN_NAMESPACE: u8 = 6;
    const PIDFS_IOCTL_GET_TIME_NAMESPACE: u8 = 7;
    const PIDFS_IOCTL_GET_TIME_FOR_CHILDREN_NAMESPACE: u8 = 8;
    const PIDFS_IOCTL_GET_USER_NAMESPACE: u8 = 9;
    const PIDFS_IOCTL_GET_UTS_NAMESPACE: u8 = 10;
    const PIDFS_IOCTL_GET_INFO: u8 = 11;

    // FIXME: maybe replace with nix::sched::CloneFlags?
    pub enum PidfdGetNamespace {
        Cgroup,
        Ipc,
        Mnt,
        Net,
        Pid,
        PidForChildren,
        Time,
        TimeForChildren,
        User,
        Uts,
    }

    impl PidfdGetNamespace {
        // FIXME can this be called from outside?
        fn as_ioctl(&self) -> u8 {
            match self {
                PidfdGetNamespace::Cgroup => PIDFS_IOCTL_GET_CGROUP_NAMESPACE,
                PidfdGetNamespace::Ipc => PIDFS_IOCTL_GET_IPC_NAMESPACE,
                PidfdGetNamespace::Mnt => PIDFS_IOCTL_GET_MNT_NAMESPACE,
                PidfdGetNamespace::Net => PIDFS_IOCTL_GET_NET_NAMESPACE,
                PidfdGetNamespace::Pid => PIDFS_IOCTL_GET_PID_NAMESPACE,
                PidfdGetNamespace::PidForChildren => PIDFS_IOCTL_GET_PID_FOR_CHILDREN_NAMESPACE,
                PidfdGetNamespace::Time => PIDFS_IOCTL_GET_TIME_NAMESPACE,
                PidfdGetNamespace::TimeForChildren => PIDFS_IOCTL_GET_TIME_FOR_CHILDREN_NAMESPACE,
                PidfdGetNamespace::User => PIDFS_IOCTL_GET_USER_NAMESPACE,
                PidfdGetNamespace::Uts => PIDFS_IOCTL_GET_UTS_NAMESPACE,
            }
        }
    }

    pub fn pidfd_get_namespace(pidfd: RawFd, ns: &PidfdGetNamespace) -> io::Result<OwnedFd> {
        unsafe {
            let fd = cvt(libc::ioctl(
                pidfd,
                request_code_none!(PIDFS_IOCTL_MAGIC, ns.as_ioctl()),
            ))?;
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }

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

    // FIXME: don't leak nix dependency
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

        let mut info = PidfdInfo {
            mask: flags,
            ..Default::default()
        };

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

    pub fn pidfd_send_signal(pidfd: RawFd, signal: libc::c_int) -> io::Result<()> {
        cvt(unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd,
                signal,
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
            Err(e) => Err(e.into()),
        }
    }

    pub fn pidfd_get_ppid(pidfd: RawFd) -> io::Result<i32> {
        Ok(pidfd_get_info(pidfd, PidfdInfoFlags::PID).map(|info| info.ppid as i32)?)
    }

    pub struct PidfdCreds {
        pub ruid: u32,
        pub rgid: u32,
        pub euid: u32,
        pub egid: u32,
        pub suid: u32,
        pub sgid: u32,
        pub fsuid: u32,
        pub fsgid: u32,
    }

    pub fn pidfd_get_creds(pidfd: RawFd) -> io::Result<PidfdCreds> {
        Ok(
            pidfd_get_info(pidfd, PidfdInfoFlags::CREDS).map(|info| PidfdCreds {
                ruid: info.ruid,
                rgid: info.rgid,
                euid: info.euid,
                egid: info.egid,
                suid: info.suid,
                sgid: info.sgid,
                fsuid: info.fsuid,
                fsgid: info.fsgid,
            })?,
        )
    }

    pub fn pidfd_get_cgroupid(pidfd: RawFd) -> io::Result<u64> {
        Ok(pidfd_get_info(pidfd, PidfdInfoFlags::PID).map(|info| info.cgroupid)?)
    }

    pub fn pidfd_get_inode_id(pidfd: RawFd) -> io::Result<u64> {
        use nix::sys::stat::fstat;
        // FIXME make sure pidfd is actually a pidfd (check_pidfs)

        // TODO: look into name_to_handle_at

        let stat = fstat(pidfd)?;
        // FIXME make into compile time
        assert_eq!(8, std::mem::size_of_val(&stat.st_ino));

        Ok(stat.st_ino)
    }

    pub fn pidfd_getfd(pidfd: RawFd, targetfd: i32) -> io::Result<OwnedFd> {
        unsafe {
            let fd = cvt(libc::syscall(
                libc::SYS_pidfd_getfd,
                pidfd as libc::c_int,
                targetfd as libc::c_int,
                0,
            ) as libc::c_int)?;
            Ok(OwnedFd::from_raw_fd(fd as libc::c_int))
        }
    }
}

#[cfg(not(feature = "nightly"))]
mod pidfd_impl {
    use super::lowlevel::{pidfd_send_signal, pidfd_try_wait, pidfd_wait};
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::process::ExitStatus;

    pub struct PidFd(OwnedFd);

    impl PidFd {
        pub fn kill(&self) -> io::Result<()> {
            pidfd_send_signal(self.0.as_raw_fd(), libc::SIGKILL)
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

pub use lowlevel::{PidfdCreds, PidfdGetNamespace};
use lowlevel::{
    pidfd_get_cgroupid, pidfd_get_creds, pidfd_get_inode_id, pidfd_get_namespace, pidfd_get_pid,
    pidfd_get_ppid, pidfd_getfd, pidfd_open, pidfd_send_signal,
};
pub use nix::sched::CloneFlags;
#[cfg(feature = "nightly")]
pub use std::os::linux::process::PidFd;

pub trait PidFdExt {
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
    fn from_pid(pid: i32) -> io::Result<PidFd> {
        // FIXME: verify pid as pidfd (see systemd)
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

    fn get_id(&self) -> io::Result<u64> {
        pidfd_get_inode_id(self.as_raw_fd())
    }

    fn get_creds(&self) -> io::Result<PidfdCreds> {
        pidfd_get_creds(self.as_raw_fd())
    }

    fn get_cgroupid(&self) -> io::Result<u64> {
        pidfd_get_cgroupid(self.as_raw_fd())
    }

    fn get_namespace(&self, ns: &PidfdGetNamespace) -> io::Result<OwnedFd> {
        pidfd_get_namespace(self.as_raw_fd(), ns)
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
        pidfd_send_signal(self.as_raw_fd(), signal)
    }

    fn set_namespace(&self, ns: CloneFlags) -> io::Result<()> {
        Ok(nix::sched::setns(self, ns)?)
    }

    fn get_remote_fd(&self, target_fd: i32) -> io::Result<OwnedFd> {
        pidfd_getfd(self.as_raw_fd(), target_fd)
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

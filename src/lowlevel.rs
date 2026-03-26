// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use name_to_handle_at::name_to_handle_at;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
#[cfg(not(feature = "nightly"))]
use std::os::unix::process::ExitStatusExt;
#[cfg(not(feature = "nightly"))]
use std::process::ExitStatus;
use std::sync::atomic;

const PID_FS_MAGIC: i64 = 0x50494446;

#[repr(u8)]
#[derive(PartialEq)]
enum Supported {
    Unknown = 0,
    Yes = 1,
    No = 2,
}

struct AtomicSupported(atomic::AtomicU8);

impl AtomicSupported {
    const fn new(supported: Supported) -> Self {
        Self(atomic::AtomicU8::new(supported as u8))
    }

    fn load(&self) -> Supported {
        match self.0.load(atomic::Ordering::Relaxed) {
            0 => Supported::Unknown,
            1 => Supported::Yes,
            2 => Supported::No,
            _ => panic!(),
        }
    }

    fn store(&self, supported: Supported) {
        self.0.store(supported as u8, atomic::Ordering::Relaxed);
    }
}

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

/// Linux namespace types that can be queried from a pidfd.
///
/// Used with [`PidFdExt::get_namespace`](crate::PidFdExt::get_namespace) to obtain
/// a file descriptor to a specific namespace of a process.
#[non_exhaustive]
pub enum PidFdGetNamespace {
    /// Control group namespace
    Cgroup,
    /// IPC namespace (System V IPC, POSIX message queues)
    Ipc,
    /// Mount namespace (filesystem mount points)
    Mnt,
    /// Network namespace (network devices, stacks, ports, etc.)
    Net,
    /// PID namespace
    Pid,
    /// PID namespace for child processes
    PidForChildren,
    /// Time namespace
    Time,
    /// Time namespace for child processes
    TimeForChildren,
    /// User namespace (user and group IDs)
    User,
    /// UTS namespace (hostname and NIS domain name)
    Uts,
}

impl PidFdGetNamespace {
    fn as_ioctl(&self) -> u8 {
        match self {
            PidFdGetNamespace::Cgroup => PIDFS_IOCTL_GET_CGROUP_NAMESPACE,
            PidFdGetNamespace::Ipc => PIDFS_IOCTL_GET_IPC_NAMESPACE,
            PidFdGetNamespace::Mnt => PIDFS_IOCTL_GET_MNT_NAMESPACE,
            PidFdGetNamespace::Net => PIDFS_IOCTL_GET_NET_NAMESPACE,
            PidFdGetNamespace::Pid => PIDFS_IOCTL_GET_PID_NAMESPACE,
            PidFdGetNamespace::PidForChildren => PIDFS_IOCTL_GET_PID_FOR_CHILDREN_NAMESPACE,
            PidFdGetNamespace::Time => PIDFS_IOCTL_GET_TIME_NAMESPACE,
            PidFdGetNamespace::TimeForChildren => PIDFS_IOCTL_GET_TIME_FOR_CHILDREN_NAMESPACE,
            PidFdGetNamespace::User => PIDFS_IOCTL_GET_USER_NAMESPACE,
            PidFdGetNamespace::Uts => PIDFS_IOCTL_GET_UTS_NAMESPACE,
        }
    }
}

pub fn pidfd_get_namespace<Fd: AsFd>(pidfd: &Fd, ns: &PidFdGetNamespace) -> io::Result<OwnedFd> {
    // SAFETY:
    // The arguments of the ioctl depend on the ioctl number and the fd.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The ioctl number is guarantteed to be as implemented by PidFdGetNamespace::as_ioctl.
    // All those ioctl numbers have the same scheme and do not take any other argument.
    // The result is either -1 with errno, or a valid fd.
    unsafe {
        let fd = cvt(libc::ioctl(
            pidfd.as_fd().as_raw_fd(),
            nix::request_code_none!(PIDFS_IOCTL_MAGIC, ns.as_ioctl()),
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

nix::ioctl_readwrite!(
    pidfd_get_info_ioctl,
    PIDFS_IOCTL_MAGIC,
    PIDFS_IOCTL_GET_INFO,
    PidfdInfo
);

fn pidfd_get_info<Fd: AsFd>(pidfd: &Fd, flags: u64) -> io::Result<PidfdInfo> {
    assert_eq!(64, std::mem::size_of::<PidfdInfo>());

    static SUPPORTED: AtomicSupported = AtomicSupported::new(Supported::Unknown);

    let supported = SUPPORTED.load();
    if supported == Supported::No {
        return Err(io::ErrorKind::Unsupported.into());
    }

    let mut info = PidfdInfo {
        mask: flags,
        ..Default::default()
    };

    // SAFETY:
    // nix::ioctl_readwrite defines pidfd_get_info_ioctl.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The GET_INFO ioctl takes a `struct pidfd_info` as argument, which is mirrored in `struct PidfdInfo`.
    let r = unsafe { pidfd_get_info_ioctl(pidfd.as_fd().as_raw_fd(), &raw mut info) }
        .map_err(ioctl_unsupported);

    if let Err(e) = r {
        if e == nix::Error::EOPNOTSUPP {
            SUPPORTED.store(Supported::No);
        }
        return Err(io::Error::from_raw_os_error(e as i32));
    } else if supported == Supported::Unknown {
        SUPPORTED.store(Supported::Yes);
    }

    assert!(info.mask & flags == flags);
    Ok(info)
}

pub fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY:
    // The pidfd_open syscall takes arguments which are mirrored here.
    // The syscall handles arbitrary values of pid.
    // The other arguments are static and valid.
    // The result is either -1 with errno, or a valid fd.
    unsafe {
        let fd = cvt(libc::syscall(
            libc::SYS_pidfd_open,
            pid as libc::pid_t,
            0 as libc::c_uint,
        ))?;
        Ok(OwnedFd::from_raw_fd(fd as libc::c_int))
    }
}

pub fn pidfd_send_signal<Fd: AsFd>(pidfd: &Fd, signal: libc::c_int) -> io::Result<()> {
    // SAFETY:
    // The pidfd_send_signal syscall takes arguments which are mirrored here.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The syscall handles arbitrary values of signal.
    // The other arguments are static and valid.
    cvt(unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_fd().as_raw_fd() as libc::c_int,
            signal as libc::c_int,
            std::ptr::null::<()>() as *const libc::siginfo_t,
            0 as libc::c_uint,
        )
    })
    .map(drop)
}

#[cfg(not(feature = "nightly"))]
fn from_waitid_siginfo(siginfo: libc::siginfo_t) -> ExitStatus {
    // SAFETY:
    // FIXME
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
pub fn pidfd_wait<Fd: AsFd>(pidfd: &Fd) -> io::Result<ExitStatus> {
    // SAFETY:
    // FIXME I think all-zero byte-pattern is valid for libc::siginfo_t
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };

    // SAFETY:
    // FIXME not entirely sure what the safeye guarantees should be here, but...
    // The libc::P_PIDFD constant tells means the second param must be a pidfd fd.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The siginfo parameter is a zeroed struct which will be filled by the syscall.
    // WEXITED is a valid constant for the last parameter.
    cvt(unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd.as_fd().as_raw_fd() as u32,
            &raw mut siginfo,
            libc::WEXITED,
        )
    })?;
    Ok(from_waitid_siginfo(siginfo))
}

#[cfg(not(feature = "nightly"))]
pub fn pidfd_try_wait<Fd: AsFd>(pidfd: &Fd) -> io::Result<Option<ExitStatus>> {
    // SAFETY:
    // FIXME I think all-zero byte-pattern is valid for libc::siginfo_t
    let mut siginfo: libc::siginfo_t = unsafe { std::mem::zeroed() };

    // SAFETY:
    // FIXME not entirely sure what the safeye guarantees should be here, but...
    // The libc::P_PIDFD constant tells means the second param must be a pidfd fd.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The siginfo parameter is a zeroed struct which will be filled by the syscall.
    // WEXITED|WNOHANG is a valid constant for the last parameter.
    cvt(unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd.as_fd().as_raw_fd() as u32,
            &mut siginfo,
            libc::WEXITED | libc::WNOHANG,
        )
    })?;

    // SAFETY:
    // The siginfo parameter was a zeroed struct which we made sure got successfully filled by the syscall.
    if unsafe { siginfo.si_pid() } == 0 {
        Ok(None)
    } else {
        Ok(Some(from_waitid_siginfo(siginfo)))
    }
}

fn pidfd_get_pid_fdinfo<Fd: AsFd>(pidfd: &Fd) -> io::Result<i32> {
    use std::fs::read_to_string;

    let raw = pidfd.as_fd().as_raw_fd();
    let fdinfo = read_to_string(format!("/proc/self/fdinfo/{raw}"))?;
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

pub fn pidfd_get_pid<Fd: AsFd>(pidfd: &Fd) -> io::Result<i32> {
    match pidfd_get_info(pidfd, PidfdInfoFlags::PID) {
        Ok(info) => Ok(info.pid as i32),
        Err(e) if e.kind() == io::ErrorKind::Unsupported => pidfd_get_pid_fdinfo(pidfd),
        Err(e) => Err(e),
    }
}

pub fn pidfd_get_ppid<Fd: AsFd>(pidfd: &Fd) -> io::Result<i32> {
    pidfd_get_info(pidfd, PidfdInfoFlags::PID).map(|info| info.ppid as i32)
}

/// Process credential information.
///
/// Contains the various user and group IDs associated with a process.
/// Obtained via [`PidFdExt::get_creds`](crate::PidFdExt::get_creds).
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidFdCreds {
    /// Real user ID
    pub ruid: u32,
    /// Real group ID
    pub rgid: u32,
    /// Effective user ID (used for permission checks)
    pub euid: u32,
    /// Effective group ID (used for permission checks)
    pub egid: u32,
    /// Saved user ID
    pub suid: u32,
    /// Saved group ID
    pub sgid: u32,
    /// Filesystem user ID (used for filesystem operations)
    pub fsuid: u32,
    /// Filesystem group ID (used for filesystem operations)
    pub fsgid: u32,
}

pub fn pidfd_get_creds<Fd: AsFd>(pidfd: &Fd) -> io::Result<PidFdCreds> {
    pidfd_get_info(pidfd, PidfdInfoFlags::CREDS).map(|info| PidFdCreds {
        ruid: info.ruid,
        rgid: info.rgid,
        euid: info.euid,
        egid: info.egid,
        suid: info.suid,
        sgid: info.sgid,
        fsuid: info.fsuid,
        fsgid: info.fsgid,
    })
}

pub fn pidfd_get_cgroupid<Fd: AsFd>(pidfd: &Fd) -> io::Result<u64> {
    pidfd_get_info(pidfd, PidfdInfoFlags::PID).map(|info| info.cgroupid)
}

pub fn pidfd_is_on_pidfs() -> io::Result<bool> {
    use nix::sys::statfs::fstatfs;

    static SUPPORTED: AtomicSupported = AtomicSupported::new(Supported::Unknown);

    match SUPPORTED.load() {
        Supported::Unknown => (),
        Supported::Yes => return Ok(true),
        Supported::No => return Ok(false),
    }

    let self_pidfd = pidfd_open(std::process::id().try_into().unwrap())?;

    let fsstat = fstatfs(self_pidfd)?;
    if fsstat.filesystem_type().0 == PID_FS_MAGIC {
        SUPPORTED.store(Supported::Yes);
        Ok(true)
    } else {
        SUPPORTED.store(Supported::No);
        Ok(false)
    }
}

pub fn pidfd_get_inode_id<Fd: AsFd>(pidfd: &Fd) -> io::Result<u64> {
    use nix::sys::stat::fstat;

    if !pidfd_is_on_pidfs()? {
        return Err(io::ErrorKind::Unsupported.into());
    }

    match name_to_handle_at(
        &pidfd.as_fd(),
        std::path::Path::new(""),
        libc::AT_EMPTY_PATH,
    ) {
        Err(e) if e.kind() == io::ErrorKind::Unsupported => (),
        Err(e) => return Err(e),
        Ok((h, _)) => return Ok(u64::from_ne_bytes(h.handle.try_into().unwrap())),
    }

    let stat = fstat(pidfd)?;

    // stat.st_ino can be 4 bytes in 32 bit systems
    if std::mem::size_of_val(&stat.st_ino) != 8 {
        return Err(io::ErrorKind::Unsupported.into());
    }

    Ok(stat.st_ino)
}

pub fn pidfd_getfd<Fd: AsFd>(pidfd: &Fd, targetfd: i32) -> io::Result<OwnedFd> {
    // SAFETY:
    // The pidfd_getfd syscall takes arguments which are mirrored here.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The syscall handles arbitrary values of targetfd.
    // The other arguments are static and valid.
    // The result is either -1 with errno, or a valid fd.
    unsafe {
        let fd = cvt(libc::syscall(
            libc::SYS_pidfd_getfd,
            pidfd.as_fd().as_raw_fd() as libc::c_int,
            targetfd as libc::c_int,
            0 as libc::c_uint,
        ) as libc::c_int)?;
        Ok(OwnedFd::from_raw_fd(fd as libc::c_int))
    }
}

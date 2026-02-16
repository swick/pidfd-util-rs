// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

// TODO:
// - split out name_to_handle_at into new crate

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
#[cfg(not(feature = "nightly"))]
use std::os::unix::process::ExitStatusExt;
#[cfg(not(feature = "nightly"))]
use std::sync::atomic;
use std::{io, process::ExitStatus};

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

pub fn pidfd_get_namespace<Fd: AsFd>(pidfd: &Fd, ns: &PidfdGetNamespace) -> io::Result<OwnedFd> {
    // SAFETY:
    // The arguments of the ioctl depend on the ioctl number and the fd.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The ioctl number is guarantteed to be as implemented by PidfdGetNamespace::as_ioctl.
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

pub fn pidfd_get_creds<Fd: AsFd>(pidfd: &Fd) -> io::Result<PidfdCreds> {
    pidfd_get_info(pidfd, PidfdInfoFlags::CREDS).map(|info| PidfdCreds {
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

#[allow(dead_code)]
pub struct FileHandle {
    pub mount_id: i32,
    pub handle_type: i32,
    pub handle: Vec<u8>,
}

pub fn name_to_handle_at<Fd: AsFd>(
    fd: &Fd,
    path: &std::path::Path,
    flags: i32,
) -> io::Result<FileHandle> {
    #[repr(C)]
    #[derive(Default)]
    pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);

    #[repr(C)]
    #[derive(Default)]
    struct file_handle {
        handle_bytes: libc::c_uint,
        handle_type: libc::c_int,
        f_handle: __IncompleteArrayField<libc::c_uchar>,
    }

    static SUPPORTED: AtomicSupported = AtomicSupported::new(Supported::Unknown);

    let supported = SUPPORTED.load();
    if supported == Supported::No {
        return Err(io::ErrorKind::Unsupported.into());
    }

    let mut handle = file_handle::default();
    let mut mount_id = 0;
    let mut path = path.as_os_str().as_bytes().to_owned();
    path.push(0);

    // SAFETY:
    // The name_to_handle_at syscall takes arguments which are mirrored here.
    // The fd wrapped in a Pidfd is always a pidfd fd.
    // The path is a valid, empty, zero-terminated path.
    // The handle mirrors `struct file_handle` and is zero-initialized, this means file_handle.handle_bytes is also zero, so the allocated size for handle is correct.
    // The mount_id is a valid pointer to an int.
    // The syscall handles arbitrary values of flags.
    #[allow(clippy::unnecessary_cast)]
    let err = cvt(unsafe {
        libc::syscall(
            libc::SYS_name_to_handle_at,
            fd.as_fd().as_raw_fd() as libc::c_int,
            path.as_ptr() as *const libc::c_char,
            &raw mut handle as *mut file_handle,
            &raw mut mount_id as *mut libc::c_int,
            flags,
        ) as libc::c_int
    })
    .unwrap_err();

    if err.raw_os_error().unwrap() == libc::EOPNOTSUPP {
        SUPPORTED.store(Supported::No);
    } else if supported == Supported::Unknown {
        SUPPORTED.store(Supported::Yes);
    }

    if err.raw_os_error().unwrap() != libc::EOVERFLOW || handle.handle_bytes == 0 {
        return Err(err);
    }

    loop {
        let layout = Layout::new::<file_handle>();
        let buf_layout =
            Layout::array::<libc::c_uchar>(handle.handle_bytes.try_into().unwrap()).unwrap();
        let (layout, buf_offset) = layout.extend(buf_layout).unwrap();
        let layout = layout.pad_to_align();

        // SAFETY:
        // Layout has non-zero size because file_handle has non-zero size
        let buf = unsafe { alloc_zeroed(layout) };
        // SAFETY:
        // Constructing a Box from the newly allocated, zeroed memory is valid
        let mut new_handle: Box<file_handle> = unsafe { Box::from_raw(buf as _) };
        new_handle.handle_bytes = handle.handle_bytes;
        new_handle.handle_type = handle.handle_type;

        // SAFETY:
        // Same as the previous name_to_handle_at syscall, except...
        // new_handle.handle_bytes is bigger than zero, so the memory allocated for new_handle must be bigger by that amount.
        // The code above ensures we allocated the right size.
        #[allow(clippy::unnecessary_cast)]
        let res = cvt(unsafe {
            libc::syscall(
                libc::SYS_name_to_handle_at,
                fd.as_fd().as_raw_fd() as libc::c_int,
                path.as_ptr() as *const libc::c_char,
                &raw mut *new_handle as *mut file_handle,
                &raw mut mount_id as *mut libc::c_int,
                flags,
            ) as libc::c_int
        });

        handle.handle_bytes = new_handle.handle_bytes;
        handle.handle_type = new_handle.handle_type;
        // We leak this because the memory belongs to buf
        Box::leak(new_handle);

        match res {
            Err(e) if e.raw_os_error().unwrap() == libc::EOVERFLOW => (),
            Err(e) => {
                // SAFETY:
                // buf and layout are still valid, and we must deallocate the memory to avoid memory leaks
                unsafe { dealloc(buf, layout) };
                return Err(e);
            }
            Ok(_) => {
                let h = {
                    // SAFETY:
                    // buf_offset was created from the layout to point at the char[].
                    // We allocated enough size for handle_bytes via the layout.
                    // The [u8] is thus properly aligned and non-zero.
                    // f_handle goes out of scope before we deallocate.
                    let f_handle = unsafe {
                        std::slice::from_raw_parts(
                            buf.offset(buf_offset.try_into().unwrap()),
                            handle.handle_bytes.try_into().unwrap(),
                        )
                    };

                    FileHandle {
                        mount_id,
                        handle_type: handle.handle_type,
                        handle: f_handle.to_vec(),
                    }
                };

                // SAFETY:
                // buf and layout are still valid, and we must deallocate the memory to avoid memory leaks
                unsafe { dealloc(buf, layout) };

                return Ok(h);
            }
        }
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
        Ok(h) => return Ok(u64::from_ne_bytes(h.handle.try_into().unwrap())),
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

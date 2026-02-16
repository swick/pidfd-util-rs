// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::lowlevel::{pidfd_send_signal, pidfd_try_wait, pidfd_wait};
use std::cell::OnceCell;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::process::ExitStatus;

/// A file descriptor that refers to a process.
///
/// This type represents a Linux pidfd (process file descriptor), which is a file descriptor
/// that refers to a process. Unlike traditional PIDs, pidfds cannot be reused, making them
/// safe from PID reuse race conditions.
///
/// On nightly Rust with the `nightly` feature, this re-exports `std::os::linux::process::PidFd`.
/// On stable Rust, this provides a compatible implementation.
pub struct PidFd {
    fd: OwnedFd,
    exit_status: OnceCell<io::Result<ExitStatus>>,
}

impl PidFd {
    fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            exit_status: OnceCell::new(),
        }
    }

    /// Sends `SIGKILL` to the process referred to by the pidfd.
    ///
    /// This is a convenience method equivalent to `send_signal(libc::SIGKILL)`.
    pub fn kill(&self) -> io::Result<()> {
        pidfd_send_signal(self, libc::SIGKILL)
    }

    /// Waits for the process referred to by the pidfd to exit and returns its exit status.
    ///
    /// This method blocks until the process exits. Use [`try_wait`](Self::try_wait)
    /// for a non-blocking alternative, or [`AsyncPidFd::wait`](crate::AsyncPidFd::wait)
    /// for async code.
    pub fn wait(&self) -> io::Result<ExitStatus> {
        let status = self.exit_status.get_or_init(|| pidfd_wait(self));

        match status {
            Ok(v) => Ok(*v),
            Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error().unwrap())),
        }
    }

    /// Checks if the process referred to by the pidfd has exited without blocking.
    ///
    /// Returns `Ok(Some(status))` if the process has exited, `Ok(None)` if it's still running.
    pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        pidfd_try_wait(self)
    }
}

impl AsRawFd for PidFd {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl FromRawFd for PidFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY:
        // The caller must ensure that fd is a valid Pidfd.
        unsafe { Self::new(OwnedFd::from_raw_fd(fd)) }
    }
}

impl IntoRawFd for PidFd {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl AsFd for PidFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl From<OwnedFd> for PidFd {
    fn from(fd: OwnedFd) -> Self {
        Self::new(fd)
    }
}

impl From<PidFd> for OwnedFd {
    fn from(pid_fd: PidFd) -> Self {
        pid_fd.fd
    }
}

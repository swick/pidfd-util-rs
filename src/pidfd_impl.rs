// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::lowlevel::{pidfd_send_signal, pidfd_try_wait, pidfd_wait};
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
///
/// # Examples
///
/// ```no_run
/// use pidfd_util::{PidFd, PidFdExt};
/// use std::process::Command;
///
/// # fn main() -> std::io::Result<()> {
/// // Spawn a process
/// let mut child = Command::new("sleep").arg("10").spawn()?;
///
/// // Create a pidfd
/// let pidfd = PidFd::from_pid(child.id() as i32)?;
///
/// // Send SIGKILL and wait for exit
/// pidfd.kill()?;
/// let status = pidfd.wait()?;
/// # Ok(())
/// # }
/// ```
pub struct PidFd(OwnedFd);

impl PidFd {
    /// Sends `SIGKILL` to the process.
    ///
    /// This is a convenience method equivalent to `send_signal(libc::SIGKILL)`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// pidfd.kill()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn kill(&self) -> io::Result<()> {
        pidfd_send_signal(self, libc::SIGKILL)
    }

    /// Waits for the process to exit and returns its exit status.
    ///
    /// This method blocks until the process exits. Use [`try_wait`](Self::try_wait)
    /// for a non-blocking alternative, or [`AsyncPidFd::wait`](crate::AsyncPidFd::wait)
    /// for async code.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// let status = pidfd.wait()?;
    /// println!("Process exited with: {:?}", status);
    /// # Ok(())
    /// # }
    /// ```
    pub fn wait(&self) -> io::Result<ExitStatus> {
        pidfd_wait(self)
    }

    /// Checks if the process has exited without blocking.
    ///
    /// Returns `Ok(Some(status))` if the process has exited, `Ok(None)` if it's still running.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// match pidfd.try_wait()? {
    ///     Some(status) => println!("Process exited: {:?}", status),
    ///     None => println!("Process still running"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

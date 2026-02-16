// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::PidFd;
use super::lowlevel::{PidFdCreds, PidFdGetNamespace};
use super::lowlevel::{
    pidfd_get_cgroupid, pidfd_get_creds, pidfd_get_inode_id, pidfd_get_namespace, pidfd_get_pid,
    pidfd_get_ppid, pidfd_getfd, pidfd_open, pidfd_send_signal,
};
use std::io;
use std::os::fd::OwnedFd;

pub use nix::sched::CloneFlags;

/// Extension trait providing additional operations on [`PidFd`].
///
/// This trait extends the basic `PidFd` functionality with methods for querying process
/// information, manipulating namespaces, and accessing remote file descriptors.
pub trait PidFdExt {
    /// Creates a `PidFd` for the current process.
    fn from_self() -> io::Result<PidFd>;

    /// Creates a `PidFd` from a process ID. Calling this is highly discouraged as it is racy and
    /// the resulting pidfd might not refer to the expected process.
    ///
    /// See the crate documentation for more details on how to obtain a pidfd in a race-free way.
    ///
    /// # Errors
    ///
    /// Returns an error if the process does not exist or if pidfd creation fails.
    fn from_pid(pid: i32) -> io::Result<PidFd>;

    /// Gets the process ID of the process referred to by the pidfd.
    fn get_pid(&self) -> io::Result<i32>;

    /// Gets the process ID of the parent process referred to by the pidfd.
    fn get_ppid(&self) -> io::Result<i32>;

    /// Gets a unique identifier of the process referred to by the pidfd.
    ///
    /// Returns a unique 64-bit identifier that, like a pidfd, will never be reused.
    /// This ID can be used to safely identify a process without risk of confusion
    /// with a different process, even after the original process exits.
    ///
    /// This is useful when you need to identify a process but cannot use the pidfd directly,
    /// such as:
    /// - Writing process identifiers to logs
    /// - Passing process identifiers to other processes where sending file descriptors is difficult
    /// - Storing process identifiers in data structures where holding file descriptors is impractical
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Unsupported` if the kernel doesn't support retrieving a unique process ID.
    fn get_id(&self) -> io::Result<u64>;

    /// Gets the credentials (UIDs and GIDs) of the process referred to by the pidfd.
    ///
    /// Returns real, effective, saved, and filesystem UID/GID values.
    /// Requires Linux 6.9+ (uses pidfd ioctl).
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Unsupported` if the kernel doesn't support the required ioctl.
    fn get_creds(&self) -> io::Result<PidFdCreds>;

    /// Gets the cgroup ID of the process.
    ///
    /// Requires Linux 6.9+ (uses pidfd ioctl).
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Unsupported` if the kernel doesn't support the required ioctl.
    fn get_cgroupid(&self) -> io::Result<u64>;

    /// Gets a file descriptor to a namespace of type `ns` of the process referred to by the pidfd.
    ///
    /// The returned file descriptor can be used with `setns()` to enter the namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace type is not supported or if the ioctl fails.
    fn get_namespace(&self, ns: &PidFdGetNamespace) -> io::Result<OwnedFd>;

    /// Executes a function with protection against PID reuse.
    ///
    /// This method verifies that the PID hasn't changed before and after executing
    /// the function `func`, protecting against race conditions where the process exits
    /// and the PID is reused between checks.
    ///
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::NotFound` if the PID changed during execution.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![cfg_attr(feature = "nightly", feature(linux_pidfd))]
    /// use pidfd_util::{PidFd, PidFdExt};
    /// use std::fs;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// let result = pidfd.access_proc(|| {
    ///     // This operation is protected against PID reuse
    ///     fs::read_to_string("/proc/1234/status")
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    fn access_proc<R, F: FnOnce() -> R>(&self, func: F) -> io::Result<R>;

    /// Sends a signal (e.g., `libc::SIGTERM`) to the process referred to by the pidfd.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be sent (e.g., insufficient permissions).
    fn send_signal(&self, signal: i32) -> io::Result<()>;

    /// Moves the calling process into the namespaces of the process referred to by the pidfd.
    ///
    /// The `ns` argument is a bit mask, specifying the namespaces to enter into.
    /// This is equivalent to calling `setns()` with this pidfd and the specified namespace flags.
    /// After this call, the current thread will be in the specified namespace(s) of the target process.
    ///
    /// # Errors
    ///
    /// Returns an error if `setns()` fails (e.g., insufficient permissions).
    fn set_namespace(&self, ns: CloneFlags) -> io::Result<()>;

    /// Installs a duplicate of a file descriptor from the process referred to by the pidfd in the current
    /// process.
    ///
    /// This allows accessing file descriptors from another process. The returned
    /// file descriptor refers to the same open file description as the file descriptor
    /// with the number `target_fd` in the target process.
    ///
    /// Requires `CAP_SYS_PTRACE` or `PTRACE_MODE_ATTACH_REALCREDS` permissions.
    ///
    /// # Errors
    ///
    /// Returns an error if permissions are insufficient or the target FD doesn't exist.
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

    fn get_creds(&self) -> io::Result<PidFdCreds> {
        pidfd_get_creds(self)
    }

    fn get_cgroupid(&self) -> io::Result<u64> {
        pidfd_get_cgroupid(self)
    }

    fn get_namespace(&self, ns: &PidFdGetNamespace) -> io::Result<OwnedFd> {
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

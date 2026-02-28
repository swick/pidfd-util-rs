// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::PidFd;
use super::lowlevel::{PidfdCreds, PidfdGetNamespace};
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
///
/// # Examples
///
/// ```no_run
/// use pidfd_util::{PidFd, PidFdExt};
///
/// # fn main() -> std::io::Result<()> {
/// // Create a pidfd for the current process
/// let pidfd = PidFd::from_self()?;
///
/// // Query various process attributes
/// let pid = pidfd.get_pid()?;
/// let ppid = pidfd.get_ppid()?;
/// let creds = pidfd.get_creds()?;
///
/// println!("PID: {}, PPID: {}, EUID: {}", pid, ppid, creds.euid);
/// # Ok(())
/// # }
/// ```
pub trait PidFdExt {
    /// Creates a `PidFd` for the current process.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let self_pidfd = PidFd::from_self()?;
    /// # Ok(())
    /// # }
    /// ```
    fn from_self() -> io::Result<PidFd>;

    /// Creates a `PidFd` from a process ID.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID to create a pidfd for
    ///
    /// # Errors
    ///
    /// Returns an error if the process does not exist or if pidfd creation fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// # Ok(())
    /// # }
    /// ```
    fn from_pid(pid: i32) -> io::Result<PidFd>;

    /// Gets the process ID associated with this pidfd.
    ///
    /// Uses modern pidfd ioctls when available (Linux 6.9+), falls back to
    /// reading `/proc/self/fdinfo` on older kernels.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// let pid = pidfd.get_pid()?;
    /// assert_eq!(pid, 1234);
    /// # Ok(())
    /// # }
    /// ```
    fn get_pid(&self) -> io::Result<i32>;

    /// Gets the parent process ID of the process associated with this pidfd.
    ///
    /// Requires Linux 6.9+ (uses pidfd ioctl). Returns an error on older kernels.
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Unsupported` if the kernel doesn't support the required ioctl.
    fn get_ppid(&self) -> io::Result<i32>;

    /// Gets a unique identifier for this process.
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

    /// Gets the credentials (UIDs and GIDs) of the process.
    ///
    /// Returns real, effective, saved, and filesystem UID/GID values.
    /// Requires Linux 6.9+ (uses pidfd ioctl).
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Unsupported` if the kernel doesn't support the required ioctl.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_self()?;
    /// let creds = pidfd.get_creds()?;
    /// println!("Effective UID: {}, GID: {}", creds.euid, creds.egid);
    /// # Ok(())
    /// # }
    /// ```
    fn get_creds(&self) -> io::Result<PidfdCreds>;

    /// Gets the cgroup ID of the process.
    ///
    /// Requires Linux 6.9+ (uses pidfd ioctl).
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::Unsupported` if the kernel doesn't support the required ioctl.
    fn get_cgroupid(&self) -> io::Result<u64>;

    /// Gets a file descriptor to a namespace of the process.
    ///
    /// The returned file descriptor can be used with `setns()` to enter the namespace.
    /// Requires Linux 6.9+ (uses pidfd ioctl).
    ///
    /// # Arguments
    ///
    /// * `ns` - The type of namespace to retrieve
    ///
    /// # Errors
    ///
    /// Returns an error if the namespace type is not supported or if the ioctl fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt, PidfdGetNamespace};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// let netns = pidfd.get_namespace(&PidfdGetNamespace::Net)?;
    /// // Use netns with setns() to enter the network namespace
    /// # Ok(())
    /// # }
    /// ```
    fn get_namespace(&self, ns: &PidfdGetNamespace) -> io::Result<OwnedFd>;

    /// Executes a function with protection against PID reuse.
    ///
    /// This method verifies that the PID hasn't changed before and after executing
    /// the function, protecting against race conditions where the process exits and
    /// the PID is reused between checks.
    ///
    /// # Arguments
    ///
    /// * `func` - The function to execute
    ///
    /// # Errors
    ///
    /// Returns `ErrorKind::NotFound` if the PID changed during execution.
    ///
    /// # Examples
    ///
    /// ```no_run
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

    /// Sends a signal to the process.
    ///
    /// # Arguments
    ///
    /// * `signal` - The signal number to send (e.g., `libc::SIGTERM`)
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be sent (e.g., insufficient permissions).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// pidfd.send_signal(libc::SIGTERM)?;
    /// # Ok(())
    /// # }
    /// ```
    fn send_signal(&self, signal: i32) -> io::Result<()>;

    /// Enters a namespace of the process referenced by this pidfd.
    ///
    /// This is equivalent to calling `setns()` with this pidfd and the specified namespace flags.
    /// After this call, the current thread will be in the specified namespace(s) of the target process.
    ///
    /// # Arguments
    ///
    /// * `ns` - Namespace flags indicating which namespace(s) to enter
    ///
    /// # Errors
    ///
    /// Returns an error if `setns()` fails (e.g., insufficient permissions).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    /// use nix::sched::CloneFlags;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// pidfd.set_namespace(CloneFlags::CLONE_NEWNET)?;
    /// // Now in the network namespace of process 1234
    /// # Ok(())
    /// # }
    /// ```
    fn set_namespace(&self, ns: CloneFlags) -> io::Result<()>;

    /// Gets a duplicate of a file descriptor from the remote process.
    ///
    /// This allows accessing file descriptors from another process. The returned
    /// file descriptor refers to the same open file description as the target process's
    /// file descriptor.
    ///
    /// Requires `CAP_SYS_PTRACE` or `PTRACE_MODE_ATTACH_REALCREDS` permissions.
    ///
    /// # Arguments
    ///
    /// * `target_fd` - The file descriptor number in the remote process
    ///
    /// # Errors
    ///
    /// Returns an error if permissions are insufficient or the target FD doesn't exist.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pidfd_util::{PidFd, PidFdExt};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// // Get a copy of FD 3 from process 1234
    /// let remote_fd = pidfd.get_remote_fd(3)?;
    /// # Ok(())
    /// # }
    /// ```
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

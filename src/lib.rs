// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

// FIXME: Double check docs!
// also add links to
// https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html
// https://man7.org/linux/man-pages/man2/pidfd_open.2.html
// https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html
// and so on

//! Safe Rust wrapper for Linux process file descriptors (pidfd).
//!
//! This crate provides a safe, ergonomic interface to Linux's pidfd API, which represents
//! processes as file descriptors. Unlike traditional PIDs, pidfds cannot be reused after a
//! process exits, making them safe from PID reuse race conditions.
//! 
//! The typical ways to obtain a pidfd include:
//! * A call to `clone3` with `CLONE_PIDFD`. On nightly, this can be done with`std::process::Command` and
//!   `create_pidfd`.
//! * Clearing the `CLOEXEC` flag on the pidfd and `exec`ing the target process. This requires calling
//!   `libc::fcntl` with `libc::F_SETFD`.
//! * Using `sendmsg`/`recvmsg` on a UNIX socket to pass the file descriptor. This is exposed in
//!   `std::os::unix::net::UnixStream::recv_vectored_with_ancillary`.
//! 
//! While `PidFd::from_pid` also exists, the use of it should be highly discouraged. There is a race
//! condition where the process with the PID died, and a new process got assigned the same, recycled PID.
//! The resulting pidfd then refers to the new process.
//!
//! # Features
//!
//! - **Safe process operations**: Send signals, wait for exit, query process information
//! - **PID reuse protection**: Pidfds remain valid and unique even after process termination
//! - **Modern kernel support**: Uses modern kernel APIs when available, falls back to older methods
//! - **Async support**: Optional async operations via the `async` feature (enabled by default)
//! - **Nightly compatibility**: Uses stdlib's `PidFd` on nightly, provides own implementation on stable
//!
//! # Core Types
//!
//! - [`PidFd`]: The main type representing a process file descriptor
//! - [`PidFdExt`]: Extension trait providing additional operations (get PID, credentials, namespaces, etc.)
//! - [`AsyncPidFd`]: Async wrapper for waiting on process exit (requires `async` feature)
//! - [`PidFdCreds`]: Process credential information (UID, GID variants)
//! - [`PidFdGetNamespace`]: Namespace types that can be queried
//!
//! # Examples
//!
//! ```no_run
//! use pidfd_util::{PidFd, PidFdExt};
//! use std::os::linux::process::{CommandExt, ChildExt};
//! #![feature(linux_pidfd)]
//! use std::process::Command;
//!
//! # fn main() -> std::io::Result<()> {
//! // Spawn a child process
//! let mut child = Command::new("echo")
//!     .create_pidfd(true)
//!     .spawn()
//!     .expect("Failed to spawn child");
//!
//! // Get the pidfd for the child
//! let pidfd = child
//!     .into_pidfd()
//!     .expect("Failed to retrieve pidfd");
//!
//! // Query process information
//! let pid = pidfd.get_pid().expect("Failed to get the child PID");
//! let creds = pidfd.get_creds().expect("Failed to child credentials");
//! println!("Process {} running as UID {}", pid, creds.euid);
//!
//! // Send a signal
//! pidfd.send_signal(libc::SIGTERM).expect("Failed to send SIGTERM to child");
//!
//! // Wait for process to exit
//! let status = pidfd.wait().expect("Failed to wait for child to exit");
//! println!("Process exited with status: {:?}", status);
//! # Ok(())
//! # }
//! ```
//!
//! # Kernel Requirements
//!
//! - Basic pidfd support requires Linux 5.3+
//! - Some operations require newer kernels
//! - The crate automatically detects kernel capabilities and falls back to compatible methods where possible

#![cfg_attr(feature = "nightly", feature(linux_pidfd))]

mod lowlevel;
#[cfg(feature = "async")]
mod pidfd_async;
mod pidfd_ext;
#[cfg(not(feature = "nightly"))]
mod pidfd_impl;
#[cfg(test)]
mod tests;

#[cfg(not(feature = "nightly"))]
pub use pidfd_impl::*;
#[cfg(feature = "nightly")]
pub use std::os::linux::process::PidFd;

pub use lowlevel::{PidFdCreds, PidFdGetNamespace};
pub use pidfd_ext::PidFdExt;

#[cfg(feature = "async")]
pub use pidfd_async::AsyncPidFd;

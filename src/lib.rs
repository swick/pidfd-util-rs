// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe Rust wrapper for Linux process file descriptors (pidfd).
//!
//! This crate provides a safe, ergonomic interface to Linux's pidfd API, which represents
//! processes as file descriptors. Unlike traditional PIDs, pidfds cannot be reused after a
//! process exits, making them safe from PID reuse race conditions.
//!
//! The typical ways to obtain a pidfd include:
//!
//! - **Using `clone3` with `CLONE_PIDFD`**: On nightly Rust, use `std::process::Command`
//!   with `create_pidfd(true)` and then call `into_pidfd()` on the child process.
//! - **Clearing the `CLOEXEC` flag and exec'ing**: Clear the close-on-exec flag using `libc::fcntl`
//!   with `libc::F_SETFD`, then exec the target process.
//! - **Passing via UNIX socket**: Use `sendmsg`/`recvmsg` on a UNIX socket to pass the file descriptor
//!   between processes. This is exposed in `std::os::unix::net::UnixStream::recv_vectored_with_ancillary`.
//!
//! **Warning**: While `PidFd::from_pid()` exists, its use is highly discouraged. There is a race
//! condition where the process with the PID dies and a new process gets assigned the same recycled PID,
//! causing the resulting pidfd to refer to the wrong process.
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
//! # #![cfg_attr(feature = "nightly", feature(linux_pidfd))]
//! #
//! # use pidfd_util::{PidFd, PidFdExt};
//! # #[cfg(feature = "nightly")]
//! # use std::os::linux::process::{CommandExt, ChildExt};
//! # use std::process::Command;
//! #
//! # #[cfg(feature = "nightly")]
//! # fn spawn_child() -> PidFd {
//! #     // Spawn a child process with pidfd support
//! #     let mut child = Command::new("echo")
//! #         .create_pidfd(true)
//! #         .spawn()
//! #         .expect("Failed to spawn child");
//! #
//! #     // Get the pidfd for the child
//! #     child
//! #         .into_pidfd()
//! #         .expect("Failed to retrieve pidfd")
//! # }
//! #
//! # #[cfg(not(feature = "nightly"))]
//! # fn spawn_child() -> PidFd {
//! #     // Spawn a child process with pidfd support
//! #     let mut child = Command::new("echo")
//! #         .spawn()
//! #         .expect("Failed to spawn child");
//! #
//! #     // WARNING! This is racy! Don't actually do this!
//! #     PidFd::from_pid(child.id().try_into().unwrap())
//! #         .expect("Failed to retrieve pidfd")
//! # }
//! #
//! # fn main() -> std::io::Result<()> {
//! let pidfd = spawn_child();
//! // Query process information
//! let pid = pidfd.get_pid().expect("Failed to get the child PID");
//! let creds = pidfd.get_creds().expect("Failed to get child credentials");
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
//! - Some operations require newer kernels (automatically detected with fallback where possible)

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

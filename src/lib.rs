// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe Rust wrapper for Linux process file descriptors (pidfd).
//!
//! This crate provides a safe, ergonomic interface to Linux's pidfd API, which represents
//! processes as file descriptors. Unlike traditional PIDs, pidfds cannot be reused after a
//! process exits, making them safe from PID reuse race conditions.
//!
//! # Features
//!
//! - **Safe process operations**: Send signals, wait for exit, query process information
//! - **PID reuse protection**: Pidfds remain valid and unique even after process termination
//! - **Modern kernel support**: Uses modern APIs (ioctls) when available, falls back to older methods
//! - **Async support**: Optional async operations via the `async` feature (enabled by default)
//! - **Nightly compatibility**: Uses stdlib's `PidFd` on nightly, provides own implementation on stable
//!
//! # Core Types
//!
//! - [`PidFd`]: The main type representing a process file descriptor
//! - [`PidFdExt`]: Extension trait providing additional operations (get PID, credentials, namespaces, etc.)
//! - [`AsyncPidFd`]: Async wrapper for waiting on process exit (requires `async` feature)
//! - [`PidfdCreds`]: Process credential information (UID, GID variants)
//! - [`PidfdGetNamespace`]: Namespace types that can be queried
//!
//! # Examples
//!
//! ```no_run
//! use pidfd_util::{PidFd, PidFdExt};
//! use std::process::Command;
//!
//! # fn main() -> std::io::Result<()> {
//! // Spawn a child process
//! let child = Command::new("sleep").arg("10").spawn()?;
//!
//! // Create a pidfd from the child's PID
//! let pidfd = PidFd::from_pid(child.id() as i32)?;
//!
//! // Query process information
//! let pid = pidfd.get_pid()?;
//! let creds = pidfd.get_creds()?;
//! println!("Process {} running as UID {}", pid, creds.euid);
//!
//! // Send a signal
//! pidfd.send_signal(libc::SIGTERM)?;
//!
//! // Wait for process to exit
//! let status = pidfd.wait()?;
//! println!("Process exited with status: {:?}", status);
//! # Ok(())
//! # }
//! ```
//!
//! # Kernel Requirements
//!
//! - Basic pidfd support requires Linux 5.3+
//! - Some operations require newer kernels (e.g., pidfd ioctls require Linux 6.9+)
//! - The crate automatically detects kernel capabilities and falls back to compatible methods

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

pub use lowlevel::{PidfdCreds, PidfdGetNamespace};
pub use pidfd_ext::PidFdExt;

#[cfg(feature = "async")]
pub use pidfd_async::AsyncPidFd;

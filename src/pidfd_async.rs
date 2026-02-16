// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::PidFd;
use async_io::Async;
use std::io;
use std::process::ExitStatus;

impl TryFrom<PidFd> for AsyncPidFd {
    type Error = io::Error;

    fn try_from(pifd: PidFd) -> Result<Self, io::Error> {
        Ok(Self(Async::new(pifd)?))
    }
}

/// An async wrapper around [`PidFd`] for asynchronous process waiting.
///
/// This type allows waiting for a process to exit asynchronously, integrating with
/// async runtimes via the `async-io` crate. The pidfd becomes readable when the
/// process exits.
///
/// Only available when the `async` feature is enabled (which is the default).
pub struct AsyncPidFd(Async<PidFd>);

impl AsyncPidFd {
    /// Asynchronously waits for the process to exit and returns its exit status.
    ///
    /// This method waits until the pidfd becomes readable (which happens when the
    /// process exits), then retrieves the exit status.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// #![cfg_attr(feature = "nightly", feature(linux_pidfd))]
    /// use pidfd_util::{PidFd, PidFdExt, AsyncPidFd};
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let pidfd = PidFd::from_pid(1234)?;
    /// let async_pidfd: AsyncPidFd = pidfd.try_into()?;
    /// let status = async_pidfd.wait().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn wait(&self) -> io::Result<ExitStatus> {
        self.0.readable().await?;
        self.0.get_ref().wait()
    }
}

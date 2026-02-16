// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

// FIXME: add docs

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

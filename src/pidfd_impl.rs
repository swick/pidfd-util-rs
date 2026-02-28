// SPDX-FileCopyrightText: 2026 The pidfd-util-rs authors
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::lowlevel::{pidfd_send_signal, pidfd_try_wait, pidfd_wait};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::process::ExitStatus;

pub struct PidFd(OwnedFd);

impl PidFd {
    pub fn kill(&self) -> io::Result<()> {
        pidfd_send_signal(self, libc::SIGKILL)
    }

    pub fn wait(&self) -> io::Result<ExitStatus> {
        pidfd_wait(self)
    }

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

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

pub trait PidFdExt {
    fn from_self() -> io::Result<PidFd>;

    fn from_pid(pid: i32) -> io::Result<PidFd>;

    fn get_pid(&self) -> io::Result<i32>;

    fn get_ppid(&self) -> io::Result<i32>;

    fn get_id(&self) -> io::Result<u64>;

    fn get_creds(&self) -> io::Result<PidfdCreds>;

    fn get_cgroupid(&self) -> io::Result<u64>;

    fn get_namespace(&self, ns: &PidfdGetNamespace) -> io::Result<OwnedFd>;

    fn access_proc<R, F: FnOnce() -> R>(&self, func: F) -> io::Result<R>;

    fn send_signal(&self, signal: i32) -> io::Result<()>;

    fn set_namespace(&self, ns: CloneFlags) -> io::Result<()>;

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

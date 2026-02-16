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

pub struct AsyncPidFd(Async<PidFd>);

impl AsyncPidFd {
    pub async fn wait(&self) -> io::Result<ExitStatus> {
        self.0.readable().await?;
        self.0.get_ref().wait()
    }
}

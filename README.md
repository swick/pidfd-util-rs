# pidfd-util-rs

Safe Rust wrapper for Linux process file descriptors (pidfd).

This crate provides a safe, ergonomic interface to Linux's pidfd API, which represents processes as file descriptors. Unlike traditional PIDs, pidfds cannot be reused after a process exits, making them safe from PID reuse race conditions.

## Features

- **Safe process operations**: Send signals, wait for exit, query process information
- **PID reuse protection**: Pidfds remain valid and unique even after process termination
- **Modern kernel support**: Uses modern kernel APIs when available, falls back to older methods
- **Async support**: Optional async operations via the `async` feature (enabled by default)
- **Nightly compatibility**: Uses stdlib's `PidFd` on nightly, provides own implementation on stable

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
pidfd-util = { version = "0.1.0", git = "https://github.com/swick/pidfd-util-rs.git" }
```

## Obtaining a PidFd

The typical ways to obtain a pidfd include:

- **Using `clone3` with `CLONE_PIDFD`**: On nightly Rust, use `std::process::Command` with `create_pidfd(true)` and then call `into_pidfd()` on the child process.
- **Clearing the `CLOEXEC` flag and exec'ing**: Clear the close-on-exec flag using `libc::fcntl` with `libc::F_SETFD`, then exec the target process.
- **Passing via UNIX socket**: Use `sendmsg`/`recvmsg` on a UNIX socket to pass the file descriptor between processes. This is exposed in `std::os::unix::net::UnixStream::recv_vectored_with_ancillary`.

⚠️ **Warning**: While `PidFd::from_pid()` exists, its use is highly discouraged. There is a race condition where the process with the PID dies and a new process gets assigned the same recycled PID, causing the resulting pidfd to refer to the wrong process.

## Usage

### Basic Example (Nightly)

```rust
use pidfd_util::{PidFd, PidFdExt};
use std::os::linux::process::{CommandExt, ChildExt};
#![feature(linux_pidfd)]
use std::process::Command;

fn main() -> std::io::Result<()> {
    // Spawn a child process with pidfd support
    let mut child = Command::new("echo")
        .create_pidfd(true)
        .spawn()
        .expect("Failed to spawn child");

    // Get the pidfd for the child
    let pidfd = child
        .into_pidfd()
        .expect("Failed to retrieve pidfd");

    // Query process information
    let pid = pidfd.get_pid().expect("Failed to get the child PID");
    let creds = pidfd.get_creds().expect("Failed to get child credentials");
    println!("Process {} running as UID {}", pid, creds.euid);

    // Send a signal
    pidfd.send_signal(libc::SIGTERM).expect("Failed to send SIGTERM to child");

    // Wait for process to exit
    let status = pidfd.wait().expect("Failed to wait for child to exit");
    println!("Process exited with status: {:?}", status);

    Ok(())
}
```

### Async Example

```rust
use pidfd_util::{PidFd, PidFdExt, AsyncPidFd};

async fn example(pidfd: PidFd) -> std::io::Result<()> {
    let async_pidfd: AsyncPidFd = pidfd.try_into()?;

    // Asynchronously wait for the process to exit
    let status = async_pidfd.wait().await?;
    println!("Process exited with: {:?}", status);

    Ok(())
}
```

## Core Types

- **`PidFd`**: The main type representing a process file descriptor
- **`PidFdExt`**: Extension trait providing additional operations (get PID, credentials, namespaces, etc.)
- **`AsyncPidFd`**: Async wrapper for waiting on process exit (requires `async` feature)
- **`PidfdCreds`**: Process credential information (UID, GID variants)
- **`PidfdGetNamespace`**: Namespace types that can be queried

## Key Operations

### Process Information

- `get_pid()` - Get the process ID of the process referred to by the pidfd
- `get_ppid()` - Get the parent process ID
- `get_id()` - Get a unique, non-reusable process identifier (useful for logging)
- `get_creds()` - Get process credentials (UIDs/GIDs)
- `get_cgroupid()` - Get the cgroup ID

### Process Control

- `kill()` - Send SIGKILL to the process
- `send_signal()` - Send any signal to the process
- `wait()` - Wait for process exit (blocking)
- `try_wait()` - Check if process has exited (non-blocking)

### Advanced Operations

- `get_namespace()` - Get a file descriptor to a process namespace
- `set_namespace()` - Move the calling process into a namespace of the target process
- `get_remote_fd()` - Duplicate a file descriptor from another process
- `access_proc()` - Execute a function with PID reuse protection

## Kernel Requirements

- Basic pidfd support requires **Linux 5.3+**
- Some operations require newer kernels (automatically detected with fallback where possible)

## Cargo Features

- `async` (default): Enables `AsyncPidFd` for async process waiting
- `nightly`: Uses stdlib's `PidFd` implementation on nightly Rust

## License

This project is licensed under either of:

- MIT License
- Apache License, Version 2.0

at your option.

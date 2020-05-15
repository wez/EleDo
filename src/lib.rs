use std::ffi::OsStr;
use std::io::Error as IoError;
use std::os::windows::ffi::OsStrExt;

mod bridge;
mod command;
mod pipe;
mod process;
mod procthreadattr;
mod psuedocon;
mod sid;
mod spawn;
mod token;

pub use bridge::{locate_pty_bridge, BridgeClient, BridgeServer, ServerPipePaths};
pub use command::Command;
pub use spawn::spawn_with_reduced_privileges;
pub use token::PrivilegeLevel;
pub use token::Token;

fn win32_error_with_context(context: &str, err: IoError) -> IoError {
    IoError::new(err.kind(), format!("{}: {}", context, err))
}

fn os_str_to_null_terminated_vec(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

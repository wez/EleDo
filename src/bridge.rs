use std::ffi::OsString;
use std::io::{Error as IoError, Result as IoResult};
use std::path::PathBuf;

/// A command to be run by the bridge
pub struct BridgeCommand {
    executable: PathBuf,
    cmdline: OsString,
    env: Vec<u16>,
    cwd: PathBuf,
}

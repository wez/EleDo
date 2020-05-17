use crate::bridge::BridgeServer;
use crate::command::*;
use crate::{PrivilegeLevel, Token};
use std::convert::TryInto;
use std::io::Result as IoResult;

/// Spawn a copy of the current process using the provided token.
/// The existing streams are passed through to the child.
/// On success, does not return to the caller; it will terminate
/// the current process and assign the exit status from the child.
fn spawn_with_current_io_streams(token: &Token) -> IoResult<()> {
    let mut cmd = Command::with_environment_for_token(token)?;
    cmd.set_command_from_current_process()?;
    let proc = cmd.spawn_as_user(token)?;

    proc.wait_for(None)?;

    let exit_code = proc.exit_code()?;
    std::process::exit(exit_code.try_into().unwrap());
}

/// If the token is PrivilegeLevel::NotPrivileged then this function
/// will return `Ok` and the intent is that the host program continue
/// with its normal operation.
///
/// Otherwise, assuming no errors were detected, this function will
/// not return to the caller.  Instead a reduced privilege token
/// will be created and used to spawn a copy of the host program,
/// passing through the arguments from the current process.
/// *This* process will remain running to bridge pipes for the stdio
/// streams to the new process and to wait for the child process
/// and then terminate *this* process and exit with the exit code
/// from the child.
pub fn spawn_with_reduced_privileges(token: &Token) -> IoResult<()> {
    let level = token.privilege_level()?;

    match level {
        PrivilegeLevel::NotPrivileged => Ok(()),
        PrivilegeLevel::Elevated => {
            let target_token = Token::with_shell_process()?;
            let mut server = BridgeServer::new();
            let mut argv = std::env::args_os().collect();
            let mut bridge_cmd = server.start_for_command(&mut argv, &target_token)?;
            let proc = bridge_cmd.spawn_with_token(&target_token)?;
            std::process::exit(server.serve(proc)? as _);
        }
        PrivilegeLevel::HighIntegrityAdmin => {
            let medium_token = token.as_medium_integrity_safer_token()?;
            spawn_with_current_io_streams(&medium_token)
        }
    }
}

/// If the token is NOT PrivilegeLevel::NotPrivileged then this function
/// will return `Ok` and the intent is that the host program continue
/// with its normal operation.
///
/// Otherwise, assuming no errors were detected, this function will
/// not return to the caller.  Instead an elevated privilege token
/// will be created and used to spawn a copy of the host program,
/// passing through the arguments from the current process.
/// *This* process will remain running to bridge pipes for the stdio
/// streams to the new process and to wait for the child process
/// and then terminate *this* process and exit with the exit code
/// from the child.
pub fn spawn_with_elevated_privileges(token: &Token) -> IoResult<()> {
    let level = token.privilege_level()?;

    let target_token = match level {
        PrivilegeLevel::NotPrivileged => token.as_medium_integrity_safer_token()?,
        PrivilegeLevel::HighIntegrityAdmin | PrivilegeLevel::Elevated => return Ok(()),
    };

    let mut server = BridgeServer::new();
    let mut argv = std::env::args_os().collect();
    let mut bridge_cmd = server.start_for_command(&mut argv, &target_token)?;
    let proc = bridge_cmd.spawn_with_token(&target_token)?;
    std::process::exit(server.serve(proc)? as _);
}

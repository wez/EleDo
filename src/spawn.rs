use crate::command::*;
use crate::pipe::*;
use crate::{PrivilegeLevel, Token};
use std::convert::TryInto;
use std::io::Result as IoResult;
use winapi::um::winbase::INFINITE;

/// Spawn a copy of the current process using the provided token.
/// The existing streams are passed through to the child.
/// On success, does not return to the caller; it will terminate
/// the current process and assign the exit status from the child.
fn spawn_with_current_io_streams(token: &Token) -> IoResult<()> {
    let mut cmd = Command::with_environment_for_token(token)?;
    cmd.set_command_from_current_process()?;
    let proc = cmd.spawn_as_user(token)?;

    proc.wait_for(INFINITE)?;

    let exit_code = proc.exit_code()?;
    std::process::exit(exit_code.try_into().unwrap());
}

/// Spawn a copy of the current process with the provided token.
/// A fresh console is allocated (not through choice!)
/// and a set of pipes established between the current process
/// and the new child that will pass through the associated
/// stdio streams.
/// On success, does not return to the caller; it will terminate
/// the current process and assign the exit status from the child.
fn spawn_with_piped_streams(token: &Token) -> IoResult<()> {
    let stdin_pipe = PipePair::new()?;
    let stdout_pipe = PipePair::new()?;
    let stderr_pipe = PipePair::new()?;

    let mut cmd = Command::with_environment_for_token(token)?;
    cmd.set_command_from_current_process()?;
    cmd.set_stdin(stdin_pipe.read)?;
    cmd.set_stdout(stdout_pipe.write)?;
    cmd.set_stderr(stderr_pipe.write)?;

    let proc = cmd.spawn_with_token(&token)?;
    drop(cmd);

    let mut stdin_pipe = stdin_pipe.write;
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let _ = std::io::copy(&mut stdin.lock(), &mut stdin_pipe);
    });

    let mut stdout_pipe = stdout_pipe.read;
    let stdout = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        let _ = std::io::copy(&mut stdout_pipe, &mut stdout.lock());
    });

    let mut stderr_pipe = stderr_pipe.read;
    let stderr = std::thread::spawn(move || {
        let stderr = std::io::stderr();
        let _ = std::io::copy(&mut stderr_pipe, &mut stderr.lock());
    });

    proc.wait_for(INFINITE)?;

    // Make sure we have a chance to flush output before we terminate
    let _ = stdout.join();
    let _ = stderr.join();

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
            // A "regular" elevated session cannot have its elevated-ness
            // removed via Token::as_medium_integrity_safer_token()
            // so we have to use the shell process token instead.
            // Fortunately(?) regular elevated sessions should always
            // be running in a context where there is a shell process.
            let shell_token = Token::with_shell_process()?;
            spawn_with_piped_streams(&shell_token)
        }
        PrivilegeLevel::HighIntegrityAdmin => {
            let medium_token = token.as_medium_integrity_safer_token()?;
            spawn_with_current_io_streams(&medium_token)
        }
    }
}

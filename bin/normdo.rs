use deelevate::{BridgeServer, Command, PrivilegeLevel, Token};
use std::convert::TryInto;

fn main() -> std::io::Result<()> {
    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;

    let target_token = match level {
        PrivilegeLevel::NotPrivileged | PrivilegeLevel::HighIntegrityAdmin => {
            token.as_medium_integrity_safer_token()?
        }
        PrivilegeLevel::Elevated => Token::with_shell_process()?,
    };

    let mut server = BridgeServer::new();

    let bridge_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "failed to locate ptybridge.exe")
        })?
        .join("ptybridge.exe");

    let pipe_path = server.start(&target_token)?;
    let mut bridge_cmd = Command::with_environment_for_token(&target_token)?;
    bridge_cmd.set_cmdline(format!("{} {}", bridge_path.display(), pipe_path).into());
    bridge_cmd.set_executable(bridge_path);

    let _bridge_proc = match level {
        PrivilegeLevel::Elevated => bridge_cmd.spawn_with_token(&target_token)?,
        PrivilegeLevel::NotPrivileged | PrivilegeLevel::HighIntegrityAdmin => {
            bridge_cmd.spawn_as_user(&target_token)?
        }
    };

    let mut command = Command::with_environment_for_token(&target_token)?;
    command.set_executable("C:\\Windows\\System32\\whoami.exe".into());
    command.set_cmdline("whoami /groups".into());
    server.set_command(command);

    let exit_code = server.run()?;
    std::process::exit(exit_code.try_into().unwrap());
}

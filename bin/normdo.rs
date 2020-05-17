use deelevate::{BridgeServer, Command, PrivilegeLevel, Token};
use pathsearch::find_executable_in_path;
use std::ffi::OsString;

fn main() -> std::io::Result<()> {
    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;

    let mut argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    if argv.is_empty() {
        eprintln!("USAGE: normdo COMMAND [ARGS]...");
        eprintln!("No command or arguments were specified");
        std::process::exit(1);
    }

    argv[0] = match find_executable_in_path(&argv[0]) {
        Some(path) => path.into(),
        None => {
            eprintln!("Unable to find {:?} in path", argv[0]);
            std::process::exit(1);
        }
    };

    let target_token = match level {
        PrivilegeLevel::NotPrivileged => token,
        PrivilegeLevel::HighIntegrityAdmin => token.as_medium_integrity_safer_token()?,
        PrivilegeLevel::Elevated => Token::with_shell_process()?,
    };

    let mut command = Command::with_environment_for_token(&target_token)?;

    let exit_code = match level {
        PrivilegeLevel::NotPrivileged => {
            // We're already normal, so just run it directly
            command.set_argv(argv);
            let proc = command.spawn()?;
            let _ = proc.wait_for(None);
            proc.exit_code()?
        }
        PrivilegeLevel::HighIntegrityAdmin | PrivilegeLevel::Elevated => {
            let mut server = BridgeServer::new();

            let mut bridge_cmd = server.start_for_command(&mut argv, &target_token)?;

            let proc = match level {
                PrivilegeLevel::Elevated => bridge_cmd.spawn_with_token(&target_token)?,
                PrivilegeLevel::NotPrivileged | PrivilegeLevel::HighIntegrityAdmin => {
                    bridge_cmd.spawn_as_user(&target_token)?
                }
            };

            server.serve(proc)?
        }
    };

    std::process::exit(exit_code as _);
}

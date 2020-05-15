use deelevate::{BridgeServer, Command, PrivilegeLevel, Token};
use pathsearch::find_executable_in_path;
use std::convert::TryInto;
use std::ffi::{OsStr, OsString};

fn main() -> std::io::Result<()> {
    let token = Token::with_current_process()?;
    let level = token.privilege_level()?;

    let mut argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    if argv.is_empty() {
        eprintln!("USAGE: eledo COMMAND [ARGS]...");
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
        PrivilegeLevel::NotPrivileged | PrivilegeLevel::HighIntegrityAdmin => {
            token.as_medium_integrity_safer_token()?
        }
        PrivilegeLevel::Elevated => Token::with_shell_process()?,
    };

    let mut command = Command::with_environment_for_token(&target_token)?;
    let argv: Vec<&OsStr> = argv.iter().map(|s| s.as_os_str()).collect();
    command.set_argv(&argv);

    let exit_code = match level {
        PrivilegeLevel::Elevated | PrivilegeLevel::HighIntegrityAdmin => {
            // We already have privs, so just run it directly
            let proc = command.spawn()?;
            let _ = proc.wait_for(None);
            proc.exit_code()?
        }
        PrivilegeLevel::NotPrivileged => {
            let mut server = BridgeServer::new();

            let bridge_path = std::env::current_exe()?
                .parent()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "failed to locate ptybridge.exe")
                })?
                .join("ptybridge.exe");

            let pipe_path = server.start(&target_token)?;
            let mut bridge_cmd = Command::with_environment_for_token(&target_token)?;
            bridge_cmd.set_argv(&[bridge_path.as_os_str(), OsStr::new(&pipe_path)]);
            bridge_cmd.hide_window();

            bridge_cmd.shell_execute("runas")?;

            server.set_command(command);
            server.run()?
        }
    };
    std::process::exit(exit_code.try_into().unwrap());
}

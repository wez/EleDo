use deelevate::{locate_pty_bridge, BridgeServer, Command, PrivilegeLevel, Token};
use pathsearch::find_executable_in_path;
use std::ffi::OsString;

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

    let exit_code = match level {
        PrivilegeLevel::Elevated | PrivilegeLevel::HighIntegrityAdmin => {
            // We already have privs, so just run it directly
            command.set_argv(argv);
            let proc = command.spawn()?;
            let _ = proc.wait_for(None);
            proc.exit_code()?
        }
        PrivilegeLevel::NotPrivileged => {
            let mut server = BridgeServer::new();

            let bridge_path = locate_pty_bridge()?;

            let mut bridge_args = server.start(&target_token)?;
            bridge_args.insert(0, bridge_path.into_os_string());
            bridge_args.push("--".into());
            bridge_args.append(&mut argv);

            let mut bridge_cmd = Command::with_environment_for_token(&target_token)?;
            bridge_cmd.set_argv(bridge_args);
            bridge_cmd.hide_window();

            let proc = bridge_cmd.shell_execute("runas")?;
            server.serve(proc)?
        }
    };
    std::process::exit(exit_code as _);
}

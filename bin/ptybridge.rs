// Don't create a new standard console window when launched from the windows GUI.
//#![windows_subsystem = "windows"]

use deelevate::{BridgeClient, ServerPipePaths};
use std::path::PathBuf;
use structopt::*;

/// A helper program for `eledo` and `normdo` that is used to
/// bridge pty and pipes between the different privilege levels.
/// This utility is not intended to be run by humans.
#[derive(StructOpt)]
struct Opt {
    /// Specifies the pipe path for the BridgeClient
    #[structopt(long, parse(from_os_str))]
    server_to_client: PathBuf,

    #[structopt(long, parse(from_os_str))]
    client_to_server: PathBuf,
}

fn main() -> std::io::Result<()> {
    let opt = Opt::from_args();
    let pipe_paths = ServerPipePaths {
        server_to_client: opt.server_to_client,
        client_to_server: opt.client_to_server,
    };
    let client = BridgeClient::with_pipe_paths(&pipe_paths)?;
    client.run()
}

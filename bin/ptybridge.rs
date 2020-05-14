// Don't create a new standard console window when launched from the windows GUI.
#![windows_subsystem = "windows"]

use deelevate::BridgeClient;

fn main() -> std::io::Result<()> {
    let pipe_path = std::env::args()
        .nth(1)
        .expect("a single argument specifying a control pipe path");
    let client = BridgeClient::with_pipe_name(pipe_path)?;
    client.run()
}

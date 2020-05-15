use crate::command::Command;
use crate::pipe::*;
use crate::process::Process;
use crate::Token;
use serde::*;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::os::windows::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;
use winapi::shared::minwindef::DWORD;
use winapi::um::fileapi::GetFileType;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winbase::FILE_TYPE_CHAR;

#[derive(Serialize, Deserialize)]
pub enum InputEvent {
    /// Only valid before StartCommand.
    /// Allocate a pty and record whether stdin, stdout, stderr
    /// should be set to the pty input/output streams.
    /// If false then they will be connected to the pipes.
    AllocatePty {
        /// true if stdin in the child will be connected to the
        /// pty rather than directly to the output pipe
        stdin: bool,
        stdout: bool,
        stderr: bool,
        /// Initial width, height of the pty
        width: usize,
        height: usize,
        /// Initial cursor position in the pty
        cursor_x: usize,
        cursor_y: usize,
    },
    /// Only valid if a pty has been allocated; change its size.
    ResizePty { width: usize, height: usize },
    /// Spawn the requested command
    StartCommand(Command),
    /// Pass data to the stdin stream of the command
    Stdin(Vec<u8>),
    /// Pass data to the input stream of the pty
    Conin(Vec<u8>),
}

impl InputEvent {
    pub fn next<R: AsRawHandle + Read>(r: &mut R) -> IoResult<Self> {
        let buf = read_message(r)?;
        let event: Self =
            bincode::deserialize(&buf).map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
        Ok(event)
    }

    pub fn write<W: Write>(&self, w: &mut W) -> IoResult<()> {
        let data =
            bincode::serialize(self).map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
        write_message(w, &data)
    }
}

#[derive(Serialize, Deserialize)]
pub enum OutputEvent {
    Started,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Conout(Vec<u8>),
    Completed(DWORD),
}

impl OutputEvent {
    pub fn next<R: AsRawHandle + Read>(r: &mut R) -> IoResult<Self> {
        let buf = read_message(r)?;
        let event: Self =
            bincode::deserialize(&buf).map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
        Ok(event)
    }

    pub fn write<W: Write>(&self, w: &mut W) -> IoResult<()> {
        let data =
            bincode::serialize(self).map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
        write_message(w, &data)
    }
}

pub struct BridgeClient {
    client_to_server: PipeHandle,
    server_to_client: PipeHandle,
}

impl BridgeClient {
    pub fn with_pipe_name<P: AsRef<Path>>(p: P) -> IoResult<Self> {
        let p = p.as_ref();
        let server_to_client = PipeHandle::open_pipe(format!("{}S2C", p.display()))?;
        let mut client_to_server = PipeHandle::open_pipe(format!("{}C2S", p.display()))?;

        OutputEvent::Started.write(&mut client_to_server)?;
        Ok(Self {
            client_to_server,
            server_to_client,
        })
    }

    pub fn run(self) -> IoResult<()> {
        let (stdin_tx, stdin_rx) = channel::<Vec<u8>>();
        let (output_tx, output_rx) = channel::<OutputEvent>();
        let (proc_tx, proc_rx) = channel::<Process>();

        std::thread::spawn({
            let mut pipe = self.client_to_server;
            move || {
                while let Ok(event) = output_rx.recv() {
                    if event.write(&mut pipe).is_err() {
                        break;
                    }
                }
            }
        });

        let stdout_pipe = PipePair::new()?;
        let stdout_thread = std::thread::spawn({
            let mut stdout = stdout_pipe.read;
            let tx = output_tx.clone();
            move || {
                let mut buf = [0u8; 4096];
                while let Ok(len) = stdout.read(&mut buf) {
                    if len == 0 {
                        break;
                    }
                    if !tx.send(OutputEvent::Stdout(buf[0..len].to_vec())).is_ok() {
                        break;
                    }
                }
            }
        });

        let stderr_pipe = PipePair::new()?;
        let stderr_thread = std::thread::spawn({
            let mut stderr = stderr_pipe.read;
            let tx = output_tx.clone();
            move || {
                let mut buf = [0u8; 4096];
                while let Ok(len) = stderr.read(&mut buf) {
                    if len == 0 {
                        break;
                    }
                    if !tx.send(OutputEvent::Stderr(buf[0..len].to_vec())).is_ok() {
                        break;
                    }
                }
            }
        });

        let stdin_pipe = PipePair::new()?;
        std::thread::spawn({
            let mut stdin = stdin_pipe.write;
            move || {
                while let Ok(data) = stdin_rx.recv() {
                    if !stdin.write_all(&data).is_ok() {
                        break;
                    }
                }
            }
        });

        let stdin = stdin_pipe.read;
        let stdout = stdout_pipe.write;
        let stderr = stderr_pipe.write;

        std::thread::spawn({
            let inputs = self.server_to_client;
            move || {
                let _ =
                    Self::process_input_events(inputs, stdin_tx, stdin, stdout, stderr, proc_tx);
            }
        });

        let proc = proc_rx.recv().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "rx proc handle from channel")
        })?;

        let _ = proc.wait_for(None);
        let exit_code = proc.exit_code().unwrap_or(1);
        let _ = output_tx.send(OutputEvent::Completed(exit_code));

        let _ = stdout_thread.join();
        let _ = stderr_thread.join();

        Ok(())
    }

    fn process_input_events(
        mut pipe: PipeHandle,
        stdin_tx: Sender<Vec<u8>>,
        stdin: PipeHandle,
        stdout: PipeHandle,
        stderr: PipeHandle,
        proc_tx: Sender<Process>,
    ) -> IoResult<()> {
        let mut started = false;

        let mut stdin = Some(stdin);
        let mut stdout = Some(stdout);
        let mut stderr = Some(stderr);

        loop {
            let input_event = InputEvent::next(&mut pipe)?;
            match input_event {
                InputEvent::AllocatePty { .. } => unimplemented!(),
                InputEvent::ResizePty { .. } => unimplemented!(),
                InputEvent::StartCommand(mut command) => {
                    assert!(!started, "we already started a command");

                    command.set_stdin(stdin.take().unwrap())?;
                    command.set_stdout(stdout.take().unwrap())?;
                    command.set_stderr(stderr.take().unwrap())?;

                    let proc = command.spawn()?;
                    proc_tx.send(proc).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "routing proc handle to channel",
                        )
                    })?;

                    started = true;
                }
                InputEvent::Stdin(data) => {
                    stdin_tx.send(data).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "routing Stdin data to channel",
                        )
                    })?;
                }
                InputEvent::Conin(_) => {
                    unimplemented!();
                }
            }
        }
    }
}

/// The bridge server is the originator of the spawned command.
/// It owns the server end of the connection and awaits the
/// bridge client connection.
#[derive(Default)]
pub struct BridgeServer {
    pipe_name: String,

    stdin_is_pty: bool,
    stdout_is_pty: bool,
    stderr_is_pty: bool,

    /*
    conin: Option<PipeHandle>,
    conout: Option<PipeHandle>,
    */
    command: Option<Command>,
    pipe_server_to_client: Option<PipeHandle>,
    pipe_client_to_server: Option<PipeHandle>,
}

fn is_pty_stream<F: AsRawHandle>(f: &F) -> bool {
    let handle = f.as_raw_handle();
    unsafe { GetFileType(handle as _) == FILE_TYPE_CHAR }
}

impl BridgeServer {
    pub fn new() -> Self {
        let pipe_name = format!(
            "\\\\.\\pipe\\eledo-bridge-{:x}-{:x}",
            unsafe { GetCurrentProcessId() },
            rand::random::<u32>()
        );

        let stdin_is_pty = is_pty_stream(&std::io::stdin());
        let stdout_is_pty = is_pty_stream(&std::io::stdout());
        let stderr_is_pty = is_pty_stream(&std::io::stderr());

        Self {
            pipe_name,
            stdin_is_pty,
            stdout_is_pty,
            stderr_is_pty,
            ..Default::default()
        }
    }

    pub fn set_command(&mut self, cmd: Command) {
        self.command.replace(cmd);
    }

    fn reader(mut self, started_tx: Sender<()>, exit_code_tx: Sender<DWORD>) -> IoResult<()> {
        let cmd = self.command.take().unwrap();
        let mut server_to_client = self.pipe_server_to_client.take().unwrap();
        let mut client_to_server = self.pipe_client_to_server.take().unwrap();

        server_to_client.wait_for_pipe_client()?;
        client_to_server.wait_for_pipe_client()?;

        // Send initial data to client here
        // TODO: pty init

        InputEvent::StartCommand(cmd).write(&mut server_to_client)?;

        // Wait for startup response

        match OutputEvent::next(&mut client_to_server)? {
            OutputEvent::Started => {
                // let Self::run know that we started up
                started_tx
                    .send(())
                    .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;
            }
            _ => {
                return Err(IoError::new(
                    std::io::ErrorKind::Other,
                    "expected Started response",
                ))
            }
        };

        // Spawn a thread with a dup'd handle to manage a queue of
        // input events and do blocking message writes to pipe.
        let (pipe_tx, pipe_rx) = channel::<InputEvent>();
        std::thread::spawn({
            let mut pipe = server_to_client;
            move || {
                while let Ok(input_event) = pipe_rx.recv() {
                    if input_event.write(&mut pipe).is_err() {
                        break;
                    }
                }
            }
        });

        // Spawn a thread for stdin to convert reads to messages
        // that are queued to the pipe writer
        std::thread::spawn({
            let pipe_tx = pipe_tx.clone();
            move || {
                let mut buf = [0u8; 4096];
                while let Ok(len) = std::io::stdin().read(&mut buf) {
                    if len == 0 {
                        break;
                    }

                    if pipe_tx
                        .send(InputEvent::Stdin(buf[0..len].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        });

        // TODO: same for conin, resize events

        let (stdout_tx, stdout_rx) = channel::<Vec<u8>>();
        let stdout_thread = std::thread::spawn(move || {
            while let Ok(buf) = stdout_rx.recv() {
                if std::io::stdout().write_all(&buf).is_err() {
                    break;
                }
            }
        });

        let (stderr_tx, stderr_rx) = channel::<Vec<u8>>();
        let stderr_thread = std::thread::spawn(move || {
            while let Ok(buf) = stderr_rx.recv() {
                if std::io::stderr().write_all(&buf).is_err() {
                    break;
                }
            }
        });

        // TODO: If conin is a tty, spawn a thread to read it and pass
        // data to pipe writer.

        let result =
            move || -> IoResult<()> {
                loop {
                    let output_event = OutputEvent::next(&mut client_to_server)?;
                    match output_event {
                        OutputEvent::Started => unreachable!(),
                        OutputEvent::Conout(data) | OutputEvent::Stdout(data) => stdout_tx
                            .send(data)
                            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?,
                        OutputEvent::Stderr(data) => stderr_tx
                            .send(data)
                            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?,
                        OutputEvent::Completed(exit_code) => exit_code_tx
                            .send(exit_code)
                            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?,
                    }
                }
            }();

        // Ensure that we flush any pending output!
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();

        result
    }

    /// Creates the server pipe and returns the name of the pipe
    /// so that it can be passed to the client process
    pub fn start(&mut self, token: &Token) -> IoResult<String> {
        self.pipe_server_to_client
            .replace(PipeHandle::create_named_pipe_byte_mode_for_token(
                format!("{}S2C", self.pipe_name),
                token,
            )?);
        self.pipe_client_to_server
            .replace(PipeHandle::create_named_pipe_byte_mode_for_token(
                format!("{}C2S", self.pipe_name),
                token,
            )?);
        Ok(self.pipe_name.clone())
    }

    pub fn run(self) -> IoResult<DWORD> {
        let (started_tx, started_rx) = channel();
        let (finished_tx, finished_rx) = channel();
        let (exit_code_tx, exit_code_rx) = channel();

        // Spawn a thread to do blocking message reads and dispatch
        // to output streams.
        std::thread::spawn(move || {
            let _ = self.reader(started_tx, exit_code_tx);
            let _ = finished_tx.send(());
        });

        // Wait for the process to start up
        started_rx.recv_timeout(Duration::new(10, 0)).map_err(|_| {
            IoError::new(
                std::io::ErrorKind::TimedOut,
                "pty bridge did not start in a timely fashion",
            )
        })?;

        // Wait for buffers to flush
        finished_rx.recv().map_err(|_| {
            IoError::new(
                std::io::ErrorKind::Other,
                "Error while waiting for pty bridge completion",
            )
        })?;

        exit_code_rx
            .recv()
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))
    }
}

fn write_message<W: Write>(w: &mut W, buf: &[u8]) -> IoResult<()> {
    leb128::write::unsigned(w, buf.len() as u64)?;
    w.write_all(buf)
}

fn read_message<R: AsRawHandle + Read>(r: &mut R) -> IoResult<Vec<u8>> {
    let size = leb128::read::unsigned(r).map_err(|e| match e {
        leb128::read::Error::IoError(e) => e,
        leb128::read::Error::Overflow => {
            IoError::new(std::io::ErrorKind::Other, "size is larger than u64")
        }
    })? as usize;
    let mut buf = vec![0u8; size];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn locate_pty_bridge() -> IoResult<PathBuf> {
    let bridge_name = "ptybridge.exe";
    let bridge_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "current exe has no containing dir while locating pty bridge!?",
            )
        })?
        .join(bridge_name);
    if bridge_path.exists() {
        Ok(bridge_path)
    } else {
        pathsearch::find_executable_in_path(bridge_name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{} not found alongside executable or in the path",
                    bridge_name
                ),
            )
        })
    }
}

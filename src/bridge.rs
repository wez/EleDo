use crate::command::Command;
use crate::pipe::*;
use crate::process::Process;
use crate::psuedocon::PsuedoCon;
use crate::win32_error_with_context;
use crate::Token;
use serde::*;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::os::windows::prelude::*;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;
use winapi::shared::minwindef::DWORD;
use winapi::um::consoleapi::{ReadConsoleInputW, SetConsoleMode};
use winapi::um::fileapi::GetFileType;
use winapi::um::winbase::FILE_TYPE_CHAR;
use winapi::um::wincon::{
    GetConsoleScreenBufferInfo, CONSOLE_SCREEN_BUFFER_INFO, DISABLE_NEWLINE_AUTO_RETURN,
    ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
    ENABLE_WRAP_AT_EOL_OUTPUT, KEY_EVENT, MOUSE_EVENT, WINDOW_BUFFER_SIZE_EVENT,
};
use winapi::um::wincontypes::{COORD, INPUT_RECORD};

#[derive(Serialize, Deserialize)]
pub enum InputEvent {
    /// Only valid before StartCommand.
    /// Allocate a pty and record whether stdin, stdout, stderr
    /// should be set to the pty input/output streams.
    /// If false then they will be connected to the pipes.
    AllocatePty {
        /// true if stdin in the child will be connected to the
        /// pty rather than directly to the output pipe
        stdin_is_pty: bool,
        stdout_is_pty: bool,
        stderr_is_pty: bool,
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
    Conin(char),
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
    pub fn with_pipe_paths(paths: &ServerPipePaths) -> IoResult<Self> {
        let server_to_client = PipeHandle::open_pipe(&paths.server_to_client)?;
        let mut client_to_server = PipeHandle::open_pipe(&paths.client_to_server)?;

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
            let output_tx = output_tx.clone();
            move || {
                let _ = Self::process_input_events(
                    inputs, stdin_tx, stdin, stdout, stderr, proc_tx, output_tx,
                );
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
        output_tx: Sender<OutputEvent>,
    ) -> IoResult<()> {
        let mut started = false;

        let mut stdin = Some(stdin);
        let mut stdout = Some(stdout);
        let mut stderr = Some(stderr);
        let mut con = None;
        let mut con_in = None;
        let mut con_out_thread = None;
        let mut all_pty = false;

        struct ThreadJoiner(Option<std::thread::JoinHandle<()>>);
        impl Drop for ThreadJoiner {
            fn drop(&mut self) {
                if let Some(t) = self.0.take() {
                    let _ = t.join();
                }
            }
        }

        loop {
            let input_event = InputEvent::next(&mut pipe)?;
            match input_event {
                InputEvent::AllocatePty {
                    stdin_is_pty,
                    stdout_is_pty,
                    stderr_is_pty,
                    width,
                    height,
                    cursor_x,
                    cursor_y,
                } => {
                    let mut conin_pipe = PipePair::new()?;
                    let conout_pipe = PipePair::new()?;

                    // FIXME; need to separate pty and pipe processing into two separate exes
                    all_pty = stdin_is_pty && stdout_is_pty && stderr_is_pty;

                    if !all_pty && stdin_is_pty {
                        stdin.replace(conin_pipe.read.duplicate()?);
                    }
                    if !all_pty && stdout_is_pty {
                        stdout.replace(conout_pipe.write.duplicate()?);
                    }
                    if !all_pty && stderr_is_pty {
                        stderr.replace(conout_pipe.write.duplicate()?);
                    }

                    con.replace(PsuedoCon::new(
                        COORD {
                            X: width as i16,
                            Y: height as i16,
                        },
                        conin_pipe.read,
                        conout_pipe.write,
                    )?);

                    // set initial cursor position.  Not sure if this is effective.
                    write!(conin_pipe.write, "\x1b[{};{}H", cursor_y + 1, cursor_x + 1)?;

                    con_in.replace(conin_pipe.write);

                    con_out_thread.replace(ThreadJoiner(Some(std::thread::spawn({
                        let mut out = conout_pipe.read;
                        let tx = output_tx.clone();
                        move || {
                            let mut buf = [0u8; 4096];
                            while let Ok(len) = out.read(&mut buf) {
                                if len == 0 {
                                    break;
                                }
                                if !tx.send(OutputEvent::Conout(buf[0..len].to_vec())).is_ok() {
                                    break;
                                }
                            }
                        }
                    }))));
                }
                InputEvent::ResizePty { width, height } => {
                    if let Some(con) = con.as_ref() {
                        con.resize(COORD {
                            X: width as _,
                            Y: height as _,
                        })?;
                    }
                }
                InputEvent::StartCommand(mut command) => {
                    assert!(!started, "we already started a command");

                    // FIXME: figure out mixing pipes/redirection with a pty
                    let stdin = stdin.take();
                    let stdout = stdout.take();
                    let stderr = stderr.take();
                    if !all_pty {
                        command.set_stdin(stdin.unwrap())?;
                        command.set_stdout(stdout.unwrap())?;
                        command.set_stderr(stderr.unwrap())?;
                    }

                    let proc = match con.as_ref() {
                        Some(pty) => command.spawn_with_pty(pty)?,
                        None => command.spawn()?,
                    };

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
                InputEvent::Conin(c) => {
                    if let Some(con_in) = con_in.as_mut() {
                        write!(con_in, "{}", c)?;
                    }
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
    stdin_is_pty: bool,
    stdout_is_pty: bool,
    stderr_is_pty: bool,

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
        let stdin_is_pty = is_pty_stream(&std::io::stdin());
        let stdout_is_pty = is_pty_stream(&std::io::stdout());
        let stderr_is_pty = is_pty_stream(&std::io::stderr());

        Self {
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

        let con_in = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .ok();
        let con_out = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONOUT$")
            .ok();

        if con_in.is_some() && con_out.is_some() {
            // We are attached to a pty so we need to build a pty
            // on the other end of the bridge.

            unsafe {
                SetConsoleMode(
                    con_out.as_ref().unwrap().as_raw_handle() as _,
                    ENABLE_PROCESSED_OUTPUT
                        | ENABLE_WRAP_AT_EOL_OUTPUT
                        | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                        | DISABLE_NEWLINE_AUTO_RETURN,
                );
            }

            let mut console_info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
            let res = unsafe {
                GetConsoleScreenBufferInfo(
                    con_out.as_ref().unwrap().as_raw_handle() as _,
                    &mut console_info,
                )
            };

            if res == 0 {
                return Err(win32_error_with_context(
                    "GetConsoleScreenBufferInfo",
                    IoError::last_os_error(),
                ));
            }

            // The console info describes the buffer dimensions.
            // We need to do a little bit of math to obtain the viewport dimensions!
            let width = console_info
                .srWindow
                .Right
                .saturating_sub(console_info.srWindow.Left) as usize
                + 1;
            let height = console_info
                .srWindow
                .Bottom
                .saturating_sub(console_info.srWindow.Top) as usize
                + 1;

            let cursor_x = console_info.dwCursorPosition.X as usize;
            let cursor_y = console_info.dwCursorPosition.Y as usize;

            InputEvent::AllocatePty {
                stdin_is_pty: self.stdin_is_pty,
                stdout_is_pty: self.stdout_is_pty,
                stderr_is_pty: self.stderr_is_pty,
                width,
                height,
                cursor_x,
                cursor_y,
            }
            .write(&mut server_to_client)?;
        }

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
        if !self.stdin_is_pty {
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
        }

        if let Some(con_in) = con_in {
            // Handle console input and relay to the other side
            std::thread::spawn({
                let pipe_tx = pipe_tx.clone();
                move || -> IoResult<()> {
                    let mut records: [INPUT_RECORD; 128] = unsafe { std::mem::zeroed() };

                    /* FIXME: we need to restore the mode in use when we quit
                    unsafe {
                        SetConsoleMode(con_in.as_raw_handle() as _, ENABLE_VIRTUAL_TERMINAL_INPUT);
                    }
                    */

                    loop {
                        let mut num_read = 0;
                        let res = unsafe {
                            ReadConsoleInputW(
                                con_in.as_raw_handle() as _,
                                records.as_mut_ptr(),
                                records.len() as u32,
                                &mut num_read,
                            )
                        };
                        if res == 0 {
                            return Err(win32_error_with_context(
                                "ReadConsoleInputW",
                                IoError::last_os_error(),
                            ));
                        }
                        for rec in &records[0..num_read as usize] {
                            match rec.EventType {
                                KEY_EVENT => {
                                    let event = unsafe { rec.Event.KeyEvent() };
                                    if event.bKeyDown != 0 {
                                        match std::char::from_u32(*unsafe {
                                            event.uChar.UnicodeChar()
                                        }
                                            as u32)
                                        {
                                            Some(unicode) if unicode > '\x00' => {
                                                pipe_tx.send(InputEvent::Conin(unicode)).map_err(
                                                    |e| {
                                                        IoError::new(
                                                            std::io::ErrorKind::Other,
                                                            format!("{}", e),
                                                        )
                                                    },
                                                )?;
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                MOUSE_EVENT => {
                                    // TODO: propagate mouse!
                                }
                                WINDOW_BUFFER_SIZE_EVENT => {
                                    let event = unsafe { rec.Event.WindowBufferSizeEvent() };
                                    pipe_tx
                                        .send(InputEvent::ResizePty {
                                            width: event.dwSize.X as usize,
                                            height: event.dwSize.Y as usize,
                                        })
                                        .map_err(|e| {
                                            IoError::new(
                                                std::io::ErrorKind::Other,
                                                format!("{}", e),
                                            )
                                        })?;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            });
        }

        let (stdout_tx, stdout_rx) = channel::<Vec<u8>>();
        let stdout_thread = std::thread::spawn(move || {
            while let Ok(buf) = stdout_rx.recv() {
                if std::io::stdout().write_all(&buf).is_err() {
                    break;
                }
            }
        });

        let conout_tx;
        let conout_thread;

        if let Some(mut con_out) = con_out {
            let (tx, rx) = channel::<Vec<u8>>();
            conout_thread = Some(std::thread::spawn(move || {
                while let Ok(buf) = rx.recv() {
                    if con_out.write_all(&buf).is_err() {
                        break;
                    }
                }
            }));

            conout_tx = Some(tx);
        } else {
            conout_tx = None;
            conout_thread = None;
        }

        let (stderr_tx, stderr_rx) = channel::<Vec<u8>>();
        let stderr_thread = std::thread::spawn(move || {
            while let Ok(buf) = stderr_rx.recv() {
                if std::io::stderr().write_all(&buf).is_err() {
                    break;
                }
            }
        });

        let result = move || -> IoResult<()> {
            loop {
                let output_event = OutputEvent::next(&mut client_to_server)?;
                match output_event {
                    OutputEvent::Started => unreachable!(),
                    OutputEvent::Conout(data) => match conout_tx.as_ref() {
                        Some(tx) => tx
                            .send(data)
                            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?,
                        None => Err(IoError::new(
                            std::io::ErrorKind::Other,
                            "Conout when there is no conout!",
                        ))?,
                    },
                    OutputEvent::Stdout(data) => stdout_tx
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
        if let Some(conout_thread) = conout_thread {
            let _ = conout_thread.join();
        }

        result
    }

    /// Creates the server pipe and returns the name of the pipe
    /// so that it can be passed to the client process
    pub fn start(&mut self, token: &Token) -> IoResult<ServerPipePaths> {
        let server_to_client = NamedPipeServer::for_token(token)?;
        let client_to_server = NamedPipeServer::for_token(token)?;

        self.pipe_server_to_client.replace(server_to_client.pipe);
        self.pipe_client_to_server.replace(client_to_server.pipe);
        Ok(ServerPipePaths {
            server_to_client: server_to_client.path,
            client_to_server: client_to_server.path,
        })
    }

    pub fn run(self) -> IoResult<DWORD> {
        let (started_tx, started_rx) = channel();
        let (finished_tx, finished_rx) = channel();
        let (exit_code_tx, exit_code_rx) = channel();

        // Spawn a thread to do blocking message reads and dispatch
        // to output streams.
        std::thread::spawn(move || {
            if let Err(e) = self.reader(started_tx, exit_code_tx) {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    eprintln!("BridgeServer error: {:?}", e);
                }
            }
            let _ = finished_tx.send(());
        });

        // Wait for the process to start up
        started_rx
            .recv_timeout(Duration::new(10, 0))
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e))?;

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
    let bridge_name = "eledo-pty-bridge.exe";
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
pub struct ServerPipePaths {
    pub server_to_client: PathBuf,
    pub client_to_server: PathBuf,
}

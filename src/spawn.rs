use crate::win32_error_with_context;
use crate::{PrivilegeLevel, Token};
use std::convert::TryInto;
use std::io::{Error as IoError, Result as IoResult};
use std::ptr::null_mut;
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID};
use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{FlushFileBuffers, ReadFile, WriteFile};
use winapi::um::handleapi::{CloseHandle, SetHandleInformation, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::GetModuleFileNameW;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::processenv::{GetCommandLineW, GetCurrentDirectoryW, GetStdHandle};
use winapi::um::processthreadsapi::{
    CreateProcessAsUserW, GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::userenv::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use winapi::um::winbase::{
    lstrlenW, CREATE_DEFAULT_ERROR_MODE, CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP,
    CREATE_UNICODE_ENVIRONMENT, HANDLE_FLAG_INHERIT, INFINITE, STARTF_USESTDHANDLES,
    STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::{LPCWSTR, LPWSTR};

extern "system" {
    /// This is missing from the currently available versions of the winapi crate.
    fn CreateProcessWithTokenW(
        hToken: HANDLE,
        dwLogonFlags: DWORD,
        lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: *mut STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> BOOL;
}

/// A little container type for holding a pipe file handle
struct PipeHandle(HANDLE);
/// The compiler thinks it isn't send because HANDLE is a pointer
/// type.  We happen to know that moving the handle between threads
/// is totally fine, hence this impl.
unsafe impl Send for PipeHandle {}

impl PipeHandle {
    fn make_inheritable(&self) -> IoResult<()> {
        let res = unsafe { SetHandleInformation(self.0, HANDLE_FLAG_INHERIT, 1) };
        if res != 1 {
            Err(win32_error_with_context(
                "SetHandleInformation HANDLE_FLAG_INHERIT",
                IoError::last_os_error(),
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

impl std::io::Read for PipeHandle {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let mut num_read = 0;
        let ok = unsafe {
            ReadFile(
                self.0,
                buf.as_mut_ptr() as *mut _,
                buf.len() as _,
                &mut num_read,
                null_mut(),
            )
        };
        if ok == 0 {
            let err = IoError::last_os_error();
            if err.kind() == std::io::ErrorKind::BrokenPipe {
                Ok(0)
            } else {
                Err(win32_error_with_context("ReadFile", err))
            }
        } else {
            Ok(num_read as usize)
        }
    }
}

impl std::io::Write for PipeHandle {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let mut num_wrote = 0;
        let ok = unsafe {
            WriteFile(
                self.0,
                buf.as_ptr() as *const _,
                buf.len() as u32,
                &mut num_wrote,
                null_mut(),
            )
        };
        if ok == 0 {
            Err(win32_error_with_context(
                "WriteFile",
                IoError::last_os_error(),
            ))
        } else {
            Ok(num_wrote as usize)
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        if unsafe { FlushFileBuffers(self.0) } != 1 {
            Err(win32_error_with_context(
                "FlushFileBuffers",
                IoError::last_os_error(),
            ))
        } else {
            Ok(())
        }
    }
}

/// A little helper for creating a pipe
struct PipePair {
    read: PipeHandle,
    write: PipeHandle,
}

impl PipePair {
    /// Create a new pipe
    fn new() -> IoResult<Self> {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 0,
        };
        let mut read: HANDLE = INVALID_HANDLE_VALUE as _;
        let mut write: HANDLE = INVALID_HANDLE_VALUE as _;
        if unsafe { CreatePipe(&mut read, &mut write, &mut sa, 0) } == 0 {
            return Err(win32_error_with_context(
                "CreatePipe",
                IoError::last_os_error(),
            ));
        }
        Ok(Self {
            read: PipeHandle(read),
            write: PipeHandle(write),
        })
    }
}

/// Returns the path to the current executable module.
fn get_module_file_name() -> Vec<u16> {
    let mut name = vec![0u16; 1024];
    loop {
        let len = unsafe { GetModuleFileNameW(null_mut(), name.as_mut_ptr(), name.len() as u32) }
            as usize;
        // GetModuleFileNameW returns the truncated length, not the actual
        // length, so we don't have much choice but to grow exponentially
        // if our buffer wasn't large enough.
        if len == name.len() && unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER {
            name.resize(len * 2, 0);
        } else {
            name.resize(len, 0);
            return name;
        }
    }
}

fn get_current_directory() -> Vec<u16> {
    let mut name = vec![0u16; 1024];
    loop {
        let len = unsafe { GetCurrentDirectoryW(name.len() as u32, name.as_mut_ptr()) } as usize;

        let completed = len <= name.len();
        name.resize(len, 0);

        if completed {
            return name;
        }
    }
}

/// Returns the command line string in a mutable buffer.
/// We can't simply pass GetCommandLineW to the process spawning functions
/// as they do modify the text!
fn get_command_line() -> Vec<u16> {
    let mut res = vec![];
    let slice = unsafe {
        let command_line = GetCommandLineW();
        let len = lstrlenW(command_line);

        std::slice::from_raw_parts(command_line, len.try_into().unwrap())
    };
    res.extend_from_slice(slice);
    res
}

struct EnvironmentBlock(LPVOID);
impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        unsafe {
            DestroyEnvironmentBlock(self.0);
        }
    }
}

impl EnvironmentBlock {
    /// Create a copy of the current environment, but do so for the provided token.
    /// We have to do this explicitly as some of the CreateProcessAsXXX
    /// calls will default to a different process environment otherwise!
    pub fn with_token(token: &Token) -> IoResult<Self> {
        let mut block = null_mut();
        let inherit = true;
        if unsafe { CreateEnvironmentBlock(&mut block, token.token, inherit as _) } != 1 {
            Err(win32_error_with_context(
                "CreateEnvironmentBlock",
                IoError::last_os_error(),
            ))
        } else {
            Ok(Self(block))
        }
    }
}

/// Spawn a copy of the current process using the provided token.
/// The existing streams are passed through to the child.
/// On success, does not return to the caller; it will terminate
/// the current process and assign the exit status from the child.
fn spawn_with_current_io_streams(token: &Token) -> IoResult<()> {
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;

    unsafe {
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut exe_path = get_module_file_name();
    let mut command_line = get_command_line();
    let env = EnvironmentBlock::with_token(token)?;
    let mut cwd = get_current_directory();
    let proc_attributes = null_mut();
    let thread_attributes = null_mut();
    let inherit_handles = true;

    let res = unsafe {
        CreateProcessAsUserW(
            token.token,
            exe_path.as_mut_ptr(),
            command_line.as_mut_ptr(),
            proc_attributes,
            thread_attributes,
            inherit_handles as _,
            CREATE_UNICODE_ENVIRONMENT,
            env.0,
            cwd.as_mut_ptr(),
            &mut si,
            &mut pi,
        )
    };
    if res != 1 {
        return Err(win32_error_with_context(
            "CreateProcessAsUserW",
            IoError::last_os_error(),
        ));
    }

    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

    let mut exit_code = 1;
    unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) };
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
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;

    let stdin_pipe = PipePair::new()?;
    let stdout_pipe = PipePair::new()?;
    let stderr_pipe = PipePair::new()?;

    stdin_pipe.read.make_inheritable()?;
    stdout_pipe.write.make_inheritable()?;
    stderr_pipe.write.make_inheritable()?;

    si.hStdInput = stdin_pipe.read.0;
    si.hStdOutput = stdout_pipe.write.0;
    si.hStdError = stderr_pipe.write.0;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut exe_path = get_module_file_name();
    let mut command_line = get_command_line();
    let env = EnvironmentBlock::with_token(token)?;
    let mut cwd = get_current_directory();
    let logon_flags = 0;

    let res = unsafe {
        CreateProcessWithTokenW(
            token.token,
            logon_flags,
            exe_path.as_mut_ptr(),
            command_line.as_mut_ptr(),
            CREATE_UNICODE_ENVIRONMENT|
            // Note that these flags are unconditoinally or'd
            // in by CreateProcessWithTokenW: they're included
            // here to make it more obvious that these apply.
            CREATE_DEFAULT_ERROR_MODE|
            CREATE_NEW_CONSOLE|
            CREATE_NEW_PROCESS_GROUP,
            env.0,
            cwd.as_mut_ptr(),
            &mut si,
            &mut pi,
        )
    };
    if res != 1 {
        return Err(win32_error_with_context(
            "CreateProcessWithTokenW",
            IoError::last_os_error(),
        ));
    }

    drop(stdin_pipe.read);
    drop(stdout_pipe.write);
    drop(stderr_pipe.write);

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

    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
    }

    // Make sure we have a chance to flush output before we terminate
    let _ = stdout.join();
    let _ = stderr.join();

    let mut exit_code = 1;
    unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) };
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

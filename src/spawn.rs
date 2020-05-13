use crate::win32_error_with_context;
use crate::{PrivilegeLevel, Token};
use std::convert::TryInto;
use std::io::{Error as IoError, Result as IoResult};
use winapi::shared::minwindef::{BOOL, DWORD, LPVOID};
use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{FlushFileBuffers, ReadFile, WriteFile};
use winapi::um::handleapi::{CloseHandle, SetHandleInformation, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::GetModuleFileNameW;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::processenv::GetCommandLineW;
use winapi::um::processthreadsapi::{
    CreateProcessAsUserW, GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::{
    lstrlenW, HANDLE_FLAG_INHERIT, INFINITE, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES,
};
use winapi::um::winnt::HANDLE;
use winapi::um::winnt::{LPCWSTR, LPWSTR};
use winapi::um::winuser::SW_HIDE;

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
                std::ptr::null_mut(),
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
                std::ptr::null_mut(),
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
            lpSecurityDescriptor: std::ptr::null_mut(),
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
        let len = unsafe {
            GetModuleFileNameW(std::ptr::null_mut(), name.as_mut_ptr(), name.len() as u32)
        } as usize;
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
    if level == PrivilegeLevel::NotPrivileged {
        return Ok(());
    }

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // CreateProcessWithTokenW forces the use of a new console
    // window for the child process, even if we were to pass
    // down console handles from the current process, so we
    // have no choice but to proxy pipes between our parent
    // and the child.
    // While we don't strictly need to employ pipes for the
    // CreateProcessAsUserW mode of operation, we do do still
    // need to wait for the child and propagate its exit status
    // so it ends up being simpler just to use the same treatment
    // for io and windowing for both cases.
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE as _;

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

    match level {
        // A "regular" elevated session cannot have its elevated-ness
        // removed via Token::as_medium_integrity_safer_token()
        // so we have to use the shell process token instead.
        // Fortunately(?) regular elevated sessions should always
        // be running in a context where there is a shell process.
        PrivilegeLevel::Elevated => unsafe {
            let shell_token = Token::with_shell_process()?;

            let res = CreateProcessWithTokenW(
                shell_token.token,
                0,
                exe_path.as_mut_ptr(),
                command_line.as_mut_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut si,
                &mut pi,
            );
            if res != 1 {
                return Err(win32_error_with_context(
                    "CreateProcessWithTokenW",
                    IoError::last_os_error(),
                ));
            }
        },

        // eg: the ssh session case.  We have higher privilege level
        // than a regular elevated session so it's easier for us to
        // spawn a session with a simpler restricted token.
        PrivilegeLevel::HighIntegrityAdmin => unsafe {
            let medium_token = token.as_medium_integrity_safer_token()?;

            let res = CreateProcessAsUserW(
                medium_token.token,
                exe_path.as_mut_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                true as _,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut si,
                &mut pi,
            );
            if res != 1 {
                return Err(win32_error_with_context(
                    "CreateProcessAsUserW",
                    IoError::last_os_error(),
                ));
            }
        },

        PrivilegeLevel::NotPrivileged => unreachable!(),
    };

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

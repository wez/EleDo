use crate::{os_str_to_null_terminated_vec, win32_error_with_context, Token};
use std::io::{Error as IoError, Result as IoResult};
use std::os::windows::prelude::*;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::AtomicUsize;
use winapi::shared::winerror::ERROR_PIPE_CONNECTED;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile, OPEN_EXISTING};
use winapi::um::handleapi::{
    CloseHandle, DuplicateHandle, SetHandleInformation, INVALID_HANDLE_VALUE,
};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, CreatePipe};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::um::winbase::*;
use winapi::um::winnt::{DUPLICATE_SAME_ACCESS, GENERIC_READ, GENERIC_WRITE, HANDLE};

/// A little container type for holding a pipe file handle
pub struct PipeHandle(HANDLE);
/// The compiler thinks it isn't send because HANDLE is a pointer
/// type.  We happen to know that moving the handle between threads
/// is totally fine, hence this impl.
unsafe impl Send for PipeHandle {}

impl PipeHandle {
    pub fn make_inheritable(&self) -> IoResult<()> {
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

    pub fn as_handle(&self) -> HANDLE {
        self.0
    }

    pub fn create_named_pipe_byte_mode_for_token<P: AsRef<Path>>(
        name: P,
        token: &Token,
    ) -> IoResult<Self> {
        let descriptor = token.create_security_descriptor()?;

        let path = os_str_to_null_terminated_vec(name.as_ref().as_os_str());
        let max_instances = 1;
        let buf_size = 4096;
        let default_timeout_ms = 100;
        let mut security_attr = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as _,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };

        let handle = unsafe {
            CreateNamedPipeW(
                path.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                max_instances,
                buf_size,
                buf_size,
                default_timeout_ms,
                &mut security_attr,
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            Ok(Self(handle))
        } else {
            Err(win32_error_with_context(
                "CreateNamedPipeW",
                IoError::last_os_error(),
            ))
        }
    }

    pub fn wait_for_pipe_client(&self) -> IoResult<()> {
        let res = unsafe { ConnectNamedPipe(self.0, null_mut()) };
        let err = unsafe { GetLastError() };
        if res == 0 && err != ERROR_PIPE_CONNECTED {
            Err(win32_error_with_context(
                "ConnectNamedPipe",
                IoError::last_os_error(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn duplicate(&self) -> IoResult<Self> {
        let proc = unsafe { GetCurrentProcess() };
        let mut duped = INVALID_HANDLE_VALUE;
        let inheritable = false;
        let access = 0;
        let res = unsafe {
            DuplicateHandle(
                proc,
                self.0,
                proc,
                &mut duped,
                access,
                inheritable as _,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if res == 0 {
            Err(win32_error_with_context(
                "DuplicateHandle",
                IoError::last_os_error(),
            ))
        } else {
            Ok(Self(duped))
        }
    }

    pub fn open_pipe<P: AsRef<Path>>(name: P) -> IoResult<Self> {
        let path = os_str_to_null_terminated_vec(name.as_ref().as_os_str());
        let share_mode = 0;
        let security_attr = null_mut();
        let flags = 0;
        let template_file = null_mut();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                share_mode,
                security_attr,
                OPEN_EXISTING,
                flags,
                template_file,
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            Ok(Self(handle))
        } else {
            Err(win32_error_with_context(
                "CreateNamedPipeW",
                IoError::last_os_error(),
            ))
        }
    }
}

impl AsRawHandle for PipeHandle {
    fn as_raw_handle(&self) -> RawHandle {
        self.as_handle() as RawHandle
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
            Err(win32_error_with_context("ReadFile", err))
        /*
        if err.kind() == std::io::ErrorKind::BrokenPipe {
            Ok(0)
        } else {
            Err(win32_error_with_context("ReadFile", err))
        }
        */
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

pub struct NamedPipeServer {
    pub pipe: PipeHandle,
    pub path: PathBuf,
}

impl NamedPipeServer {
    pub fn for_token(token: &Token) -> IoResult<Self> {
        static ID: AtomicUsize = AtomicUsize::new(1);
        let path: PathBuf = format!(
            "\\\\.\\pipe\\eledo-bridge-{:x}-{:x}-{:x}",
            unsafe { GetCurrentProcessId() },
            ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            rand::random::<u32>()
        )
        .into();
        let pipe = PipeHandle::create_named_pipe_byte_mode_for_token(&path, token)?;
        Ok(Self { pipe, path })
    }
}

/// A little helper for creating a pipe
pub struct PipePair {
    pub read: PipeHandle,
    pub write: PipeHandle,
}

impl PipePair {
    /// Create a new pipe
    pub fn new() -> IoResult<Self> {
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

use crate::win32_error_with_context;
use std::io::{Error as IoError, Result as IoResult};
use std::ptr::null_mut;
use winapi::um::fileapi::{FlushFileBuffers, ReadFile, WriteFile};
use winapi::um::handleapi::{CloseHandle, SetHandleInformation, INVALID_HANDLE_VALUE};
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::winbase::HANDLE_FLAG_INHERIT;
use winapi::um::winnt::HANDLE;

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

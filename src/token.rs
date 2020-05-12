use crate::sid::{is_well_known, AsSid, WellKnownSid};
use std::io::{Error as IoError, Result as IoResult};
use winapi::shared::minwindef::{BOOL, DWORD};
use winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::securitybaseapi::{CheckTokenMembership, DuplicateTokenEx, GetTokenInformation};
use winapi::um::winnt::{
    SecurityImpersonation, TokenElevationType, TokenElevationTypeFull, TokenImpersonation,
    TokenIntegrityLevel, WinBuiltinAdministratorsSid, WinHighLabelSid, HANDLE, MAXIMUM_ALLOWED,
    SID, TOKEN_ELEVATION_TYPE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};

/// Indicates the effective level of privileges held by the token
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// The token isn't privileged
    NotPrivileged,
    /// The token is an elevated token produced via runas/UAC
    Elevated,
    /// The token isn't an elevated token but it does have
    /// high integrity privileges, such as those produced
    /// by sshing in to a Windows 10 system.
    HighIntegrityAdmin,
}

/// A helper that wraps a TOKEN_MANDATORY_LABEL struct.
/// That struct holds a SID and some attribute flags.
/// Its use in this module is to query the integrity level
/// of the token, so we have a very targeted set of accessors
/// for that purpose.
/// The integrity level is a single SID that represents the
/// degree of trust that the token has.
/// A normal user is typically running with Medium integrity,
/// whereas an elevated session is typically running with High
/// integrity.
struct TokenIntegrityLevel {
    data: Vec<u8>,
}

impl TokenIntegrityLevel {
    fn as_label(&self) -> &TOKEN_MANDATORY_LABEL {
        // This is safe because we cannot construct an invalid instance
        unsafe { &*(self.data.as_ptr() as *const TOKEN_MANDATORY_LABEL) }
    }

    fn sid(&self) -> *const SID {
        // For whatever reason, the PSID type in the SDK is defined
        // as void* and that is the type of Label.Sid, rather than
        // SID*, so we get to cast it here.
        self.as_label().Label.Sid as *const SID
    }

    /// Return true if this is a high integrity level label
    pub fn is_high(&self) -> bool {
        is_well_known(self.sid(), WinHighLabelSid)
    }
}

/// `Token` represents a set of credentials and privileges.  A process
/// typically inherits the token of its parent process for its primary
/// token, and Windows allows for threads to create/obtain impersonation
/// tokens so that a thread can run with a different identity for a
/// while.
///
/// For the purposes of this crate, we are concerned with reducing
/// the scope of the privileges in a given Token.
pub struct Token {
    token: HANDLE,
}

impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.token);
        }
    }
}

impl Token {
    /// Obtain a handle to the primary token for this process
    pub fn with_current_process() -> IoResult<Self> {
        let mut token: HANDLE = INVALID_HANDLE_VALUE;
        let res = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if res != 1 {
            Err(IoError::last_os_error())
        } else {
            Ok(Self { token })
        }
    }

    /// Attempt to duplicate this token as one that is suitable
    /// for use in impersonation related APIs, which includes the
    /// check_membership method.
    fn duplicate_as_impersonation_token(&self) -> IoResult<Self> {
        let mut imp: HANDLE = INVALID_HANDLE_VALUE;
        let res = unsafe {
            DuplicateTokenEx(
                self.token,
                MAXIMUM_ALLOWED,
                std::ptr::null_mut(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut imp,
            )
        };
        if res != 1 {
            Err(IoError::last_os_error())
        } else {
            Ok(Self { token: imp })
        }
    }

    /// Returns true if `sid` is an enabled group on this token.
    /// The token must be an impersonation token, so you may need
    /// to use duplicate_as_impersonation_token() to obtain one.
    fn check_membership<S: AsSid>(&self, sid: S) -> IoResult<bool> {
        let mut is_member: BOOL = 0;
        let res =
            unsafe { CheckTokenMembership(self.token, sid.as_sid() as *mut _, &mut is_member) };
        if res != 1 {
            Err(IoError::last_os_error())
        } else {
            Ok(is_member == 1)
        }
    }

    /// A convenience wrapper around check_membership that tests for
    /// being a member of the builtin administrators group
    fn check_administrators_membership(&self) -> IoResult<bool> {
        let admins = WellKnownSid::with_well_known(WinBuiltinAdministratorsSid)?;
        self.check_membership(&admins)
    }

    /// Retrieve the integrity level label of the process.
    fn integrity_level(&self) -> IoResult<TokenIntegrityLevel> {
        let mut size: DWORD = 0;
        let err;

        unsafe {
            GetTokenInformation(
                self.token,
                TokenIntegrityLevel,
                std::ptr::null_mut(),
                0,
                &mut size,
            );
            err = GetLastError();
        };

        // The call should have failed and told us we need more space
        if err != ERROR_INSUFFICIENT_BUFFER {
            return Err(IoError::last_os_error());
        }

        // Allocate and zero out the storage
        let mut data = vec![0u8; size as usize];

        unsafe {
            if GetTokenInformation(
                self.token,
                TokenIntegrityLevel,
                data.as_mut_ptr() as *mut _,
                size,
                &mut size,
            ) == 0
            {
                return Err(IoError::last_os_error());
            }
        };

        Ok(TokenIntegrityLevel { data })
    }

    /// Return an enum value that indicates the degree of elevation
    /// applied to the current token; this can be one of:
    /// TokenElevationTypeDefault, TokenElevationTypeFull,
    /// TokenElevationTypeLimited.
    fn elevation_type(&self) -> IoResult<TOKEN_ELEVATION_TYPE> {
        let mut ele_type: TOKEN_ELEVATION_TYPE = 0;
        let mut size: DWORD = 0;
        let res = unsafe {
            GetTokenInformation(
                self.token,
                TokenElevationType,
                &mut ele_type as *mut TOKEN_ELEVATION_TYPE as *mut _,
                std::mem::size_of_val(&ele_type) as u32,
                &mut size,
            )
        };
        if res != 1 {
            Err(IoError::last_os_error())
        } else {
            Ok(ele_type)
        }
    }

    /// Determine the effective privilege level of the token
    pub fn privilege_level(&self) -> IoResult<PrivilegeLevel> {
        let ele_type = self.elevation_type()?;
        if ele_type == TokenElevationTypeFull {
            return Ok(PrivilegeLevel::Elevated);
        }

        let level = self.integrity_level()?;
        if !level.is_high() {
            return Ok(PrivilegeLevel::NotPrivileged);
        }

        let imp_token = self.duplicate_as_impersonation_token()?;
        if imp_token.check_administrators_membership()? {
            Ok(PrivilegeLevel::HighIntegrityAdmin)
        } else {
            Ok(PrivilegeLevel::NotPrivileged)
        }
    }
}

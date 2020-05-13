use std::io::Error as IoError;

mod sid;
mod spawn;
mod token;

pub use spawn::spawn_with_reduced_privileges;
pub use token::PrivilegeLevel;
pub use token::Token;

fn win32_error_with_context(context: &str, err: IoError) -> IoError {
    IoError::new(err.kind(), format!("{}: {}", context, err))
}

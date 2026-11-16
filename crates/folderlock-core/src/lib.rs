//! 把一个文件夹加密成同级的 `.flock` 锁定入口，或把它解密回原来的文件夹。

mod shell;
#[cfg_attr(windows, allow(dead_code))]
mod shell_files;
mod vault;
mod wipe;

pub use shell::{notify_parent, open_folder, register_shell, shell_info, shell_registered, unregister_shell, ShellInfo};
pub use vault::{inspect_vault, lock_folder, unlock_vault, LockOptions, LockResult, SecretKind, UnlockResult, VaultInfo};

use folderlock_crypto::Error as CryptoError;

pub const MIN_PASSWORD_CHARS: usize = 8;
pub const MAX_PASSWORD_CHARS: usize = 256;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Progress {
    pub phase: &'static str,
    pub done: u64,
    pub total: u64,
    pub current: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("密码至少需要 {0} 个字符")]
    PasswordTooShort(usize),
    #[error("密码不能超过 {0} 个字符")]
    PasswordTooLong(usize),
    #[error("{0}")]
    Message(String),
}

pub(crate) fn check_password(password: &str) -> Result<(), Error> {
    let count = password.chars().count();
    if count < MIN_PASSWORD_CHARS {
        return Err(Error::PasswordTooShort(MIN_PASSWORD_CHARS));
    }
    if count > MAX_PASSWORD_CHARS {
        return Err(Error::PasswordTooLong(MAX_PASSWORD_CHARS));
    }
    Ok(())
}

pub(crate) fn message(text: impl Into<String>) -> Error {
    Error::Message(text.into())
}

pub(crate) fn io_msg(path: &std::path::Path, err: std::io::Error) -> Error {
    let hint = if err.raw_os_error() == Some(32) {
        "（文件可能正被其他程序占用）"
    } else {
        ""
    };
    message(format!("{}：{err}{hint}", display_path(path)))
}

pub(crate) fn display_path(path: &std::path::Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    }
}

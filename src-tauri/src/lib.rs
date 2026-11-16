use std::path::{Path, PathBuf};

use folderlock_core::{LockOptions, LockResult, SecretKind, UnlockResult, VaultInfo};
use tauri::Emitter;
use zeroize::Zeroize;

#[derive(Clone, serde::Serialize)]
struct Launch {
    mode: String,
    path: String,
}

pub fn run() {
    tauri::Builder::default()
        .manage(parse_launch())
        .invoke_handler(tauri::generate_handler![
            launch_context,
            lock_folder,
            unlock_vault,
            inspect_vault,
            pick_folder,
            pick_vault,
            shell_status,
            register_shell,
            unregister_shell,
            copy_text,
            open_path
        ])
        .run(tauri::generate_context!())
        .expect("启动 FolderLock 失败");
}

fn parse_launch() -> Launch {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return home();
    }
    match args[0].as_str() {
        "lock" => Launch {
            mode: "lock".into(),
            path: args.get(1).cloned().unwrap_or_default(),
        },
        "unlock" => Launch {
            mode: "unlock".into(),
            path: args.get(1).cloned().unwrap_or_default(),
        },
        other => {
            let path = PathBuf::from(other);
            if path.is_file() && is_flock(&path) {
                Launch {
                    mode: "unlock".into(),
                    path: other.to_string(),
                }
            } else if path.is_dir() {
                Launch {
                    mode: "lock".into(),
                    path: other.to_string(),
                }
            } else {
                home()
            }
        }
    }
}

fn home() -> Launch {
    Launch {
        mode: "home".into(),
        path: String::new(),
    }
}

fn is_flock(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("flock"))
}

#[tauri::command]
fn launch_context(state: tauri::State<'_, Launch>) -> Launch {
    state.inner().clone()
}

#[tauri::command]
async fn lock_folder(app: tauri::AppHandle, path: String, password: String, confirm: String) -> Result<LockResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut password = password;
        let mut confirm = confirm;
        let result = if password != confirm {
            Err("两次输入的密码不一致".to_string())
        } else {
            folderlock_core::lock_folder(Path::new(&path), &password, &LockOptions::default(), |progress| {
                let _ = app.emit("progress", &progress);
            })
            .map_err(|err| err.to_string())
        };
        password.zeroize();
        confirm.zeroize();
        result
    })
    .await
    .map_err(|err| err.to_string())?
}

#[tauri::command]
async fn unlock_vault(app: tauri::AppHandle, path: String, secret: String, recovery: bool) -> Result<UnlockResult, String> {
    let kind = if recovery { SecretKind::RecoveryKey } else { SecretKind::Password };
    tauri::async_runtime::spawn_blocking(move || {
        let mut secret = secret;
        let result = folderlock_core::unlock_vault(Path::new(&path), &secret, kind, |progress| {
            let _ = app.emit("progress", &progress);
        })
        .map_err(|err| err.to_string());
        secret.zeroize();
        result
    })
    .await
    .map_err(|err| err.to_string())?
}

#[tauri::command]
fn inspect_vault(path: String) -> Result<VaultInfo, String> {
    folderlock_core::inspect_vault(Path::new(&path)).map_err(|err| err.to_string())
}

#[tauri::command]
async fn pick_folder() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("选择要加密的文件夹")
            .pick_folder()
            .map(|path| path.display().to_string())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
async fn pick_vault() -> Option<String> {
    tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("选择保险箱")
            .add_filter("FolderLock 保险箱", &["flock"])
            .pick_file()
            .map(|path| path.display().to_string())
    })
    .await
    .ok()
    .flatten()
}

#[tauri::command]
fn shell_status() -> Result<folderlock_core::ShellInfo, String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    folderlock_core::shell_info(&exe).map_err(|err| err.to_string())
}

#[tauri::command]
fn register_shell() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|err| err.to_string())?;
    folderlock_core::register_shell(&exe).map_err(|err| err.to_string())
}

#[tauri::command]
fn unregister_shell() -> Result<(), String> {
    folderlock_core::unregister_shell().map_err(|err| err.to_string())
}

#[tauri::command]
fn copy_text(text: String) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|err| err.to_string())?;
    clipboard.set_text(text).map_err(|err| err.to_string())
}

#[tauri::command]
fn open_path(path: String) -> Result<(), String> {
    folderlock_core::open_folder(std::path::Path::new(&path)).map_err(|err| err.to_string())
}

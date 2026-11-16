use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use folderlock_core::{
    inspect_vault, lock_folder, register_shell, shell_info, shell_registered, unlock_vault, unregister_shell, LockOptions,
    Progress, SecretKind,
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "folderlock",
    version,
    about = "把文件夹加密成 .flock 锁定入口。双击该文件并输入密码即可解锁。"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 加密文件夹，原位置留下同名 .flock 文件
    Lock {
        path: PathBuf,
        /// 从标准输入读取一行密码，不回显确认
        #[arg(long)]
        password_stdin: bool,
        /// 从环境变量 FOLDERLOCK_PASSWORD 读取密码
        #[arg(long)]
        password_env: bool,
    },
    /// 解密保险箱并恢复成文件夹
    Unlock {
        path: PathBuf,
        /// 使用恢复密钥，而不是密码
        #[arg(long)]
        recovery: bool,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        password_env: bool,
    },
    /// 查看保险箱头信息，不解密文件名
    Info { path: PathBuf },
    /// 为当前用户注册资源管理器右键菜单和 .flock 关联
    Register {
        /// 图形界面 folderlock.exe 的路径。省略时在本程序旁边查找
        #[arg(long)]
        exe: Option<PathBuf>,
    },
    /// 移除右键菜单和 .flock 关联
    Unregister,
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Lock {
            path,
            password_stdin,
            password_env,
        } => lock_cmd(&path, password_stdin, password_env),
        Cmd::Unlock {
            path,
            recovery,
            password_stdin,
            password_env,
        } => unlock_cmd(&path, recovery, password_stdin, password_env),
        Cmd::Info { path } => info_cmd(&path),
        Cmd::Register { exe } => register_cmd(exe),
        Cmd::Unregister => finish(unregister_shell().map(|()| "已移除右键菜单和文件关联。".to_string())),
    }
}

fn lock_cmd(path: &Path, stdin: bool, env: bool) -> ExitCode {
    let mut password = match read_secret(stdin, env, true, false) {
        Ok(password) => password,
        Err(err) => return fail(err),
    };
    let result = lock_folder(path, &password, &LockOptions::default(), report);
    password.zeroize();
    match result {
        Ok(locked) => {
            println!("已创建锁定入口：{}", locked.vault);
            println!("恢复密钥只显示这一次。请立刻抄到密码管理器或离线保存：");
            println!("{}", locked.recovery_key);
            if let Some(err) = locked.wipe_error {
                eprintln!("警告：保险箱已写好，但原文件夹没有删除干净。{err}");
                ExitCode::from(3)
            } else {
                println!("原文件夹已清除。资源管理器若隐藏了扩展名，这个锁定入口仍显示原来的名字。");
                ExitCode::SUCCESS
            }
        }
        Err(err) => fail(err.to_string()),
    }
}

fn unlock_cmd(path: &Path, recovery: bool, stdin: bool, env: bool) -> ExitCode {
    let mut secret = match read_secret(stdin, env, false, recovery) {
        Ok(secret) => secret,
        Err(err) => return fail(err),
    };
    let kind = if recovery { SecretKind::RecoveryKey } else { SecretKind::Password };
    let result = unlock_vault(path, &secret, kind, report);
    secret.zeroize();
    match result {
        Ok(unlocked) => {
            println!("已恢复文件夹：{}", unlocked.folder);
            if let Some(err) = unlocked.remove_error {
                eprintln!("警告：{err}");
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(err) => fail(err.to_string()),
    }
}

fn info_cmd(path: &Path) -> ExitCode {
    match inspect_vault(path) {
        Ok(info) => {
            println!("FolderLock 保险箱");
            println!("大小：{} 字节", info.bytes);
            println!(
                "Argon2id：内存 {} MiB，迭代 {}，并行 {}",
                info.argon_m_kib / 1024,
                info.argon_t,
                info.argon_p
            );
            println!("内容分块：{} 字节", info.chunk_plain);
            ExitCode::SUCCESS
        }
        Err(err) => fail(err.to_string()),
    }
}

fn register_cmd(exe: Option<PathBuf>) -> ExitCode {
    let exe = match exe.or_else(find_gui) {
        Some(path) => path,
        None => {
            return fail(format!("没有找到 {}。请用 --exe 指定图形程序的路径。", gui_file_name()));
        }
    };
    match register_shell(&exe) {
        Ok(()) => {
            let registered = shell_registered(&exe).unwrap_or(false);
            if !registered {
                return fail("集成文件已写入，但回读没有成功。".into());
            }
            println!("已注册右键菜单和 .flock 关联：{}", exe.display());
            if let Ok(info) = shell_info(&exe) {
                println!("{}", info.hint);
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail(err.to_string()),
    }
}

fn gui_file_name() -> &'static str {
    if cfg!(windows) { "folderlock.exe" } else { "folderlock" }
}

fn find_gui() -> Option<PathBuf> {
    let current = std::env::current_exe().ok()?;
    let sibling = current.parent()?.join(gui_file_name());
    sibling.is_file().then_some(sibling)
}

fn read_secret(stdin: bool, env: bool, confirm: bool, recovery: bool) -> Result<String, String> {
    if stdin && env {
        return Err("不能同时从标准输入和环境变量读取密码".into());
    }
    if recovery && (stdin || env) {
        return read_stream(stdin, env);
    }
    if recovery {
        print!("恢复密钥（输入时可见）：");
        io::stdout().flush().ok();
        return read_line();
    }
    if stdin || env {
        return read_stream(stdin, env);
    }
    let mut first = rpassword::prompt_password("密码：").map_err(|err| err.to_string())?;
    if confirm {
        let mut second = rpassword::prompt_password("再输入一次密码：").map_err(|err| err.to_string())?;
        if first != second {
            first.zeroize();
            second.zeroize();
            return Err("两次输入的密码不一致".into());
        }
        second.zeroize();
    }
    Ok(first)
}

fn read_stream(stdin: bool, env: bool) -> Result<String, String> {
    if env {
        std::env::var("FOLDERLOCK_PASSWORD").map_err(|_| "没有设置环境变量 FOLDERLOCK_PASSWORD".to_string())
    } else if stdin {
        read_line()
    } else {
        Err("没有可用的密码来源".into())
    }
}

fn read_line() -> Result<String, String> {
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|err| err.to_string())?;
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    if line.is_empty() {
        Err("输入是空的".into())
    } else {
        Ok(line)
    }
}

fn report(progress: Progress) {
    let label = match progress.phase {
        "scan" => "扫描",
        "kdf" => "派生密钥",
        "encrypt" => "加密",
        "wipe" => "清除明文",
        "decrypt" => "解密",
        "restore" => "写回",
        _ => progress.phase,
    };
    if progress.total == 0 {
        eprintln!("{label} {}", progress.current);
    } else if progress.current.is_empty() {
        eprintln!("{label} {}/{}", progress.done, progress.total);
    } else {
        eprintln!("{label} {}/{} {}", progress.done, progress.total, progress.current);
    }
}

fn finish(result: Result<String, folderlock_core::Error>) -> ExitCode {
    match result {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(err) => fail(err.to_string()),
    }
}

fn fail(message: String) -> ExitCode {
    eprintln!("错误：{message}");
    ExitCode::from(1)
}

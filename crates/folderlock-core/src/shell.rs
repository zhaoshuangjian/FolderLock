#[cfg(unix)]
use std::ffi::OsStr;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "macos")]
use crate::shell_files::{
    applescript, macos_app_plist, macos_service_info, macos_service_workflow, remove_launch_services_flock,
    upsert_launch_services, BUNDLE_ID,
};
#[cfg(all(unix, not(target_os = "macos")))]
use crate::shell_files::{
    desktop_file, dolphin_service, file_manager_script, mime_xml, remove_thunar, thunar_has_other_actions, upsert_thunar,
    MIME,
};
use crate::{display_path, io_msg, message, Error};

#[derive(Clone, Debug, serde::Serialize)]
pub struct ShellInfo {
    pub registered: bool,
    pub title: String,
    pub detail: String,
    pub hint: String,
}

pub fn shell_info(exe: &Path) -> Result<ShellInfo, Error> {
    let registered = shell_registered(exe)?;
    Ok(ShellInfo {
        registered,
        title: shell_title().into(),
        detail: if registered { shell_detail_on() } else { shell_detail_off() }.into(),
        hint: shell_hint().into(),
    })
}

pub fn open_folder(path: &Path) -> Result<(), Error> {
    let mut command = open_command();
    command
        .arg(path)
        .spawn()
        .map_err(|err| message(format!("无法打开 {}：{err}", display_path(path))))?;
    Ok(())
}

#[cfg(windows)]
fn open_command() -> Command {
    Command::new("explorer")
}

#[cfg(target_os = "macos")]
fn open_command() -> Command {
    Command::new("open")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_command() -> Command {
    Command::new("xdg-open")
}

#[cfg(windows)]
fn shell_title() -> &'static str {
    "资源管理器右键"
}

#[cfg(target_os = "macos")]
fn shell_title() -> &'static str {
    "访达右键"
}

#[cfg(all(unix, not(target_os = "macos")))]
fn shell_title() -> &'static str {
    "文件管理器右键"
}

#[cfg(windows)]
fn shell_detail_on() -> &'static str {
    "已注册。可以在文件夹上右键选择「使用 FolderLock 加密」。"
}

#[cfg(windows)]
fn shell_detail_off() -> &'static str {
    "还没有注册。注册后，右键文件夹就能加密。"
}

#[cfg(windows)]
fn shell_hint() -> &'static str {
    "Windows 11 的新版菜单里，这个命令在「显示更多选项」中。双击 .flock 会打开本程序。"
}

#[cfg(target_os = "macos")]
fn shell_detail_on() -> &'static str {
    "已注册。在文件夹上右键，打开「快速操作」或「服务」，选择「使用 FolderLock 加密」。"
}

#[cfg(target_os = "macos")]
fn shell_detail_off() -> &'static str {
    "还没有注册。注册后，访达右键可以加密，双击 .flock 可以解锁。"
}

#[cfg(target_os = "macos")]
fn shell_hint() -> &'static str {
    "如果访达没有马上出现新菜单，重新登录一次即可。双击 .flock 会打开本程序。"
}

#[cfg(all(unix, not(target_os = "macos")))]
fn shell_detail_on() -> &'static str {
    "已注册。KDE 和 XFCE 的右键菜单里有「使用 FolderLock 加密」；GNOME 和 Cinnamon 在「脚本」菜单里。"
}

#[cfg(all(unix, not(target_os = "macos")))]
fn shell_detail_off() -> &'static str {
    "还没有注册。注册后，文件管理器里可以右键加密，双击 .flock 可以解锁。"
}

#[cfg(all(unix, not(target_os = "macos")))]
fn shell_hint() -> &'static str {
    "GNOME 的加密命令在右键「脚本」中。若双击没有打开本程序，注销后重新登录。"
}

const MENU_KEY: &str = r"Software\Classes\Directory\shell\FolderLock";
const MENU_COMMAND: &str = r"Software\Classes\Directory\shell\FolderLock\command";
const EXT_KEY: &str = r"Software\Classes\.flock";
const PROGID: &str = "FolderLock.Vault";
const PROGID_KEY: &str = r"Software\Classes\FolderLock.Vault";

#[cfg(windows)]
pub fn register_shell(exe: &Path) -> Result<(), Error> {
    use winreg::enums::*;
    use winreg::RegKey;

    let exe = prepared_exe(exe)?;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey(MENU_KEY).map_err(reg_err)?;
    key.set_value("", &"使用 FolderLock 加密").map_err(reg_err)?;
    key.set_value("Icon", &format!("\"{exe}\",0")).map_err(reg_err)?;
    let (command, _) = hkcu.create_subkey(MENU_COMMAND).map_err(reg_err)?;
    command
        .set_value("", &format!("\"{exe}\" lock \"%1\""))
        .map_err(reg_err)?;

    let (ext, _) = hkcu.create_subkey(EXT_KEY).map_err(reg_err)?;
    ext.set_value("", &PROGID).map_err(reg_err)?;
    let (prog, _) = hkcu.create_subkey(PROGID_KEY).map_err(reg_err)?;
    prog.set_value("", &"FolderLock 保险箱").map_err(reg_err)?;
    let (icon, _) = hkcu.create_subkey(format!(r"{PROGID_KEY}\DefaultIcon")).map_err(reg_err)?;
    icon.set_value("", &format!("\"{exe}\",0")).map_err(reg_err)?;
    let (open, _) = hkcu
        .create_subkey(format!(r"{PROGID_KEY}\shell\open\command"))
        .map_err(reg_err)?;
    open.set_value("", &format!("\"{exe}\" unlock \"%1\"")).map_err(reg_err)?;
    Ok(())
}

#[cfg(windows)]
pub fn unregister_shell() -> Result<(), Error> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(ext) = hkcu.open_subkey(EXT_KEY) {
        let prog: String = ext.get_value("").unwrap_or_default();
        if prog == PROGID {
            let _ = hkcu.delete_subkey_all(EXT_KEY);
        }
    }
    let _ = hkcu.delete_subkey_all(PROGID_KEY);
    let _ = hkcu.delete_subkey_all(MENU_KEY);
    Ok(())
}

#[cfg(windows)]
pub fn shell_registered(exe: &Path) -> Result<bool, Error> {
    use winreg::enums::*;
    use winreg::RegKey;

    let Ok(exe) = canonical_exe(exe) else {
        return Ok(false);
    };
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(command) = hkcu.open_subkey(MENU_COMMAND) else {
        return Ok(false);
    };
    let value: String = command.get_value("").unwrap_or_default();
    Ok(value.contains(&format!("\"{exe}\"")))
}

#[cfg(windows)]
pub fn notify_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        notify(parent, 0x0000_1000);
    }
    notify(path, 0x0000_2000);
}

#[cfg(windows)]
fn notify(path: &Path, event: u32) {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        SHChangeNotify(event, 0x0005, wide.as_ptr().cast(), std::ptr::null());
    }
}

#[cfg(windows)]
fn reg_err(err: std::io::Error) -> Error {
    message(format!("写注册表失败：{err}"))
}

#[cfg(windows)]
#[link(name = "shell32")]
extern "system" {
    fn SHChangeNotify(event_id: u32, flags: u32, item1: *const std::ffi::c_void, item2: *const std::ffi::c_void);
}

#[cfg(target_os = "macos")]
pub fn register_shell(exe: &Path) -> Result<(), Error> {
    let exe = prepared_exe(exe)?;
    let home = home_dir()?;
    let support = home.join("Library/Application Support/FolderLock");
    std::fs::create_dir_all(&support).map_err(|err| io_msg(&support, err))?;
    let app = support.join("FolderLock.app");
    if app.exists() {
        std::fs::remove_dir_all(&app).map_err(|err| io_msg(&app, err))?;
    }
    let script_path = support.join("launcher.applescript");
    std::fs::write(&script_path, applescript(&exe)).map_err(|err| io_msg(&script_path, err))?;
    run("osacompile", &[OsStr::new("-o"), app.as_os_str(), script_path.as_os_str()])?;
    let _ = std::fs::remove_file(&script_path);
    let executable = macos_executable_name(&app)?;
    let plist = app.join("Contents/Info.plist");
    std::fs::write(&plist, macos_app_plist(&executable)).map_err(|err| io_msg(&plist, err))?;
    write_text(&support.join("exe-path"), &exe)?;

    let contents = home.join("Library/Services/FolderLock.workflow/Contents");
    std::fs::create_dir_all(&contents).map_err(|err| io_msg(&contents, err))?;
    write_text(&contents.join("Info.plist"), macos_service_info())?;
    write_text(&contents.join("document.wflow"), &macos_service_workflow(&exe))?;
    set_default_flock_handler(&home, true)?;
    refresh_macos(&app, false);
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn unregister_shell() -> Result<(), Error> {
    let home = home_dir()?;
    let app = home.join("Library/Application Support/FolderLock/FolderLock.app");
    refresh_macos(&app, true);
    let _ = std::fs::remove_dir_all(home.join("Library/Application Support/FolderLock"));
    let _ = std::fs::remove_dir_all(home.join("Library/Services/FolderLock.workflow"));
    set_default_flock_handler(&home, false)?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn shell_registered(exe: &Path) -> Result<bool, Error> {
    let Ok(exe) = canonical_exe(exe) else {
        return Ok(false);
    };
    let Ok(home) = home_dir() else {
        return Ok(false);
    };
    let support = home.join("Library/Application Support/FolderLock");
    let saved = std::fs::read_to_string(support.join("exe-path")).unwrap_or_default();
    let plist = std::fs::read_to_string(support.join("FolderLock.app/Contents/Info.plist")).unwrap_or_default();
    let menu = std::fs::read_to_string(home.join("Library/Services/FolderLock.workflow/Contents/Info.plist")).unwrap_or_default();
    Ok(saved.trim() == exe && plist.contains(BUNDLE_ID) && menu.contains("使用 FolderLock 加密"))
}

#[cfg(target_os = "macos")]
pub fn notify_parent(_path: &Path) {}

#[cfg(target_os = "macos")]
fn macos_executable_name(app: &Path) -> Result<String, Error> {
    let dir = app.join("Contents/MacOS");
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|err| io_msg(&dir, err))? {
        let entry = entry.map_err(|err| io_msg(&dir, err))?;
        if entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    if names.iter().any(|name| name == "applet") {
        return Ok("applet".into());
    }
    if names.iter().any(|name| name == "droplet") {
        return Ok("droplet".into());
    }
    names.into_iter().next().ok_or_else(|| message("macOS 启动器里没有可执行文件"))
}

#[cfg(target_os = "macos")]
fn set_default_flock_handler(home: &Path, present: bool) -> Result<(), Error> {
    let plist = home.join("Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist");
    if let Some(parent) = plist.parent() {
        std::fs::create_dir_all(parent).map_err(|err| io_msg(parent, err))?;
    }
    let current = if plist.is_file() {
        plist_to_xml(&plist)?
    } else if !present {
        return Ok(());
    } else {
        String::new()
    };
    let updated = if present {
        upsert_launch_services(&current, BUNDLE_ID)
    } else {
        remove_launch_services_flock(&current)
    };
    write_binary_plist(&plist, &updated)
}

#[cfg(target_os = "macos")]
fn plist_to_xml(plist: &Path) -> Result<String, Error> {
    let tmp = std::env::temp_dir().join(format!("folderlock-ls-{}.xml", std::process::id()));
    run("plutil", &[OsStr::new("-convert"), OsStr::new("xml1"), OsStr::new("-o"), tmp.as_os_str(), plist.as_os_str()])?;
    let text = std::fs::read_to_string(&tmp).map_err(|err| io_msg(&tmp, err))?;
    let _ = std::fs::remove_file(&tmp);
    Ok(text)
}

#[cfg(target_os = "macos")]
fn write_binary_plist(plist: &Path, xml: &str) -> Result<(), Error> {
    let tmp = std::env::temp_dir().join(format!("folderlock-ls-out-{}.xml", std::process::id()));
    std::fs::write(&tmp, xml).map_err(|err| io_msg(&tmp, err))?;
    run(
        "plutil",
        &[OsStr::new("-convert"), OsStr::new("binary1"), OsStr::new("-o"), plist.as_os_str(), tmp.as_os_str()],
    )?;
    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

#[cfg(target_os = "macos")]
fn refresh_macos(app: &Path, unregister: bool) {
    let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
    if Path::new(lsregister).is_file() {
        let flag = if unregister { "-u" } else { "-f" };
        run_quiet(lsregister, &[OsStr::new(flag), app.as_os_str()]);
    }
    let pbs = "/System/Library/CoreServices/pbs";
    if Path::new(pbs).is_file() {
        run_quiet(pbs, &[OsStr::new("-flush")]);
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn register_shell(exe: &Path) -> Result<(), Error> {
    let exe = prepared_exe(exe)?;
    let data = data_home()?;
    let desktop = data.join("applications/folderlock.desktop");
    write_text(&desktop, &desktop_file(&exe))?;
    let mime = data.join("mime/packages/folderlock.xml");
    write_text(&mime, mime_xml())?;
    let script = file_manager_script(&exe);
    for dir in ["nautilus/scripts", "nemo/scripts", "caja/scripts"] {
        let path = data.join(dir).join("FolderLock 加密");
        write_text(&path, &script)?;
        make_executable(&path)?;
    }
    let service = dolphin_service(&exe);
    write_text(&data.join("kio/servicemenus/folderlock.desktop"), &service)?;
    write_text(&data.join("dolphin/servicemenus/folderlock.desktop"), &service)?;
    let thunar = thunar_config()?;
    let existing = std::fs::read_to_string(&thunar).ok();
    write_text(&thunar, &upsert_thunar(existing.as_deref(), &exe))?;
    run_quiet("update-mime-database", &[data.join("mime").as_os_str()]);
    run_quiet("update-desktop-database", &[data.join("applications").as_os_str()]);
    run_quiet("xdg-mime", &[OsStr::new("default"), OsStr::new("folderlock.desktop"), OsStr::new(MIME)]);
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn unregister_shell() -> Result<(), Error> {
    let data = data_home()?;
    for relative in [
        "applications/folderlock.desktop",
        "mime/packages/folderlock.xml",
        "nautilus/scripts/FolderLock 加密",
        "nemo/scripts/FolderLock 加密",
        "caja/scripts/FolderLock 加密",
        "kio/servicemenus/folderlock.desktop",
        "dolphin/servicemenus/folderlock.desktop",
    ] {
        let _ = std::fs::remove_file(data.join(relative));
    }
    let thunar = thunar_config()?;
    if let Ok(text) = std::fs::read_to_string(&thunar) {
        let updated = remove_thunar(&text);
        if thunar_has_other_actions(&text) {
            write_text(&thunar, &updated)?;
        } else if updated.contains("<action") {
            write_text(&thunar, &updated)?;
        } else {
            let _ = std::fs::remove_file(&thunar);
        }
    }
    run_quiet("update-mime-database", &[data.join("mime").as_os_str()]);
    run_quiet("update-desktop-database", &[data.join("applications").as_os_str()]);
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn shell_registered(exe: &Path) -> Result<bool, Error> {
    let Ok(exe) = canonical_exe(exe) else {
        return Ok(false);
    };
    let Ok(data) = data_home() else {
        return Ok(false);
    };
    let desktop = std::fs::read_to_string(data.join("applications/folderlock.desktop")).unwrap_or_default();
    Ok(desktop.contains(&crate::shell_files::bash_single_quote(&exe)))
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn notify_parent(_path: &Path) {}

#[cfg(all(unix, not(target_os = "macos")))]
fn data_home() -> Result<PathBuf, Error> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg));
        }
    }
    Ok(home_dir()?.join(".local/share"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn thunar_config() -> Result<PathBuf, Error> {
    Ok(home_dir()?.join(".config/Thunar/uca.xml"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn make_executable(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path).map_err(|err| io_msg(path, err))?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).map_err(|err| io_msg(path, err))
}

#[cfg(not(any(windows, unix)))]
pub fn register_shell(_exe: &Path) -> Result<(), Error> {
    Err(message("当前系统还不能注册右键菜单"))
}

#[cfg(not(any(windows, unix)))]
pub fn unregister_shell() -> Result<(), Error> {
    Err(message("当前系统还不能注册右键菜单"))
}

#[cfg(not(any(windows, unix)))]
pub fn shell_registered(_exe: &Path) -> Result<bool, Error> {
    Ok(false)
}

#[cfg(not(any(windows, unix)))]
pub fn notify_parent(_path: &Path) {}

#[cfg(not(any(windows, unix)))]
fn shell_title() -> &'static str {
    "右键菜单"
}

#[cfg(not(any(windows, unix)))]
fn shell_detail_on() -> &'static str {
    "已注册。"
}

#[cfg(not(any(windows, unix)))]
fn shell_detail_off() -> &'static str {
    "当前系统还不能注册右键菜单。"
}

#[cfg(not(any(windows, unix)))]
fn shell_hint() -> &'static str {
    ""
}

#[cfg(not(any(windows, unix)))]
fn open_command() -> Command {
    Command::new("xdg-open")
}

fn prepared_exe(exe: &Path) -> Result<String, Error> {
    if !exe.is_file() {
        return Err(message("找不到要注册的 FolderLock 程序"));
    }
    canonical_exe(exe)
}

fn canonical_exe(exe: &Path) -> Result<String, Error> {
    let path = std::fs::canonicalize(exe).map_err(|err| io_msg(exe, err))?;
    Ok(display_path(&path))
}

#[cfg(unix)]
fn home_dir() -> Result<PathBuf, Error> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| message("找不到用户主目录"))
}

#[cfg(unix)]
fn write_text(path: &Path, text: &str) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| io_msg(parent, err))?;
    }
    std::fs::write(path, text).map_err(|err| io_msg(path, err))
}

#[cfg(unix)]
fn run(program: &str, args: &[&OsStr]) -> Result<(), Error> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| message(format!("无法运行 {program}：{err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(message(format!("{program} 失败，退出码 {}", status.code().unwrap_or(-1))))
    }
}

#[cfg(unix)]
fn run_quiet(program: &str, args: &[&OsStr]) {
    let _ = Command::new(program).args(args).status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_system_has_shell_copy() {
        let info = shell_info(Path::new("folderlock-missing")).unwrap();
        assert!(!info.registered);
        assert!(!info.title.is_empty());
        assert!(!info.detail.is_empty());
    }
}

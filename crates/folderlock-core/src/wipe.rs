use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use rand::{rngs::OsRng, RngCore};

use crate::{io_msg, message, Error};

pub(crate) fn is_reparse(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

pub(crate) fn make_writable(path: &Path) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path).map_err(|err| io_msg(path, err))?;
    let mut perms = meta.permissions();
    if perms.readonly() {
        perms.set_readonly(false);
        fs::set_permissions(path, perms).map_err(|err| io_msg(path, err))?;
    }
    Ok(())
}

/// 删除上次崩溃留下的工作文件。遇到重解析点时停止，避免顺着链接删到别处。
pub(crate) fn remove_work_path(path: &Path) -> Result<(), Error> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(io_msg(path, err)),
    };
    if is_reparse(&meta) {
        return Err(message(format!("工作路径是重解析点，已停止：{}", crate::display_path(path))));
    }
    if meta.is_dir() {
        fs::remove_dir_all(path).map_err(|err| io_msg(path, err))?;
    } else {
        fs::remove_file(path).map_err(|err| io_msg(path, err))?;
    }
    Ok(())
}

pub(crate) fn wipe_tree(root: &Path, mut on_file: impl FnMut(&Path)) -> Result<(), Error> {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    collect(root, &mut files, &mut dirs)?;
    for file in &files {
        on_file(file);
        wipe_file(file)?;
    }
    dirs.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    for dir in &dirs {
        make_writable(dir)?;
        fs::remove_dir(dir).map_err(|err| io_msg(dir, err))?;
    }
    Ok(())
}

fn collect(dir: &Path, files: &mut Vec<std::path::PathBuf>, dirs: &mut Vec<std::path::PathBuf>) -> Result<(), Error> {
    let meta = fs::symlink_metadata(dir).map_err(|err| io_msg(dir, err))?;
    if is_reparse(&meta) {
        return Err(message(format!("遇到重解析点，已停止删除：{}", crate::display_path(dir))));
    }
    if !meta.is_dir() {
        return Err(message(format!("无法删除，因为它不是文件夹：{}", crate::display_path(dir))));
    }
    dirs.push(dir.to_path_buf());
    let entries = fs::read_dir(dir).map_err(|err| io_msg(dir, err))?;
    for entry in entries {
        let entry = entry.map_err(|err| io_msg(dir, err))?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|err| io_msg(&path, err))?;
        if is_reparse(&meta) {
            return Err(message(format!("遇到重解析点，已停止删除：{}", crate::display_path(&path))));
        }
        if meta.is_dir() {
            collect(&path, files, dirs)?;
        } else if meta.is_file() {
            files.push(path);
        } else {
            return Err(message(format!("遇到无法删除的文件类型：{}", crate::display_path(&path))));
        }
    }
    Ok(())
}

fn wipe_file(path: &Path) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path).map_err(|err| io_msg(path, err))?;
    if is_reparse(&meta) || !meta.is_file() {
        return Err(message(format!("拒绝覆盖这个路径：{}", crate::display_path(path))));
    }
    make_writable(path)?;
    let len = meta.len();
    if len > 0 {
        let mut file = OpenOptions::new().write(true).open(path).map_err(|err| io_msg(path, err))?;
        let mut buf = vec![0u8; 1024 * 1024];
        let mut left = len;
        while left > 0 {
            let n = std::cmp::min(buf.len() as u64, left) as usize;
            OsRng.fill_bytes(&mut buf[..n]);
            file.write_all(&buf[..n]).map_err(|err| io_msg(path, err))?;
            left -= n as u64;
        }
        file.sync_all().map_err(|err| io_msg(path, err))?;
    }
    fs::remove_file(path).map_err(|err| io_msg(path, err))
}

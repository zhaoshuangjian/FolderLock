use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use folderlock_crypto::{
    check_kdf_params, chunk_aad, derive_kek, expected_payload_len, open, open_manifest, random_array, seal,
    seal_manifest, unwrap_master, validate_manifest, validate_rel_path, wrap_master, Entry, Header, Manifest, NonceGen,
    DEFAULT_ARGON_M_KIB, DEFAULT_ARGON_P, DEFAULT_ARGON_T, DEFAULT_CHUNK_PLAIN, HEADER_LEN,
};
use zeroize::{Zeroize, Zeroizing};

use crate::shell::notify_parent;
use crate::wipe::{is_reparse, remove_work_path, wipe_tree};
use crate::{check_password, display_path, io_msg, message, Error, Progress};

/// 生产环境使用的参数。测试可以在 crate 内部构造更轻的参数。
#[derive(Clone, Debug)]
pub struct LockOptions {
    pub(crate) argon_m_kib: u32,
    pub(crate) argon_t: u32,
    pub(crate) argon_p: u32,
    pub(crate) chunk_plain: u32,
}

impl Default for LockOptions {
    fn default() -> Self {
        Self {
            argon_m_kib: DEFAULT_ARGON_M_KIB,
            argon_t: DEFAULT_ARGON_T,
            argon_p: DEFAULT_ARGON_P,
            chunk_plain: DEFAULT_CHUNK_PLAIN,
        }
    }
}

impl LockOptions {
    fn validate(&self) -> Result<(), Error> {
        Ok(check_kdf_params(self.argon_m_kib, self.argon_t, self.argon_p, self.chunk_plain)?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    Password,
    RecoveryKey,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct LockResult {
    pub vault: String,
    pub recovery_key: String,
    pub wipe_error: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct UnlockResult {
    pub folder: String,
    pub remove_error: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct VaultInfo {
    pub bytes: u64,
    pub argon_m_kib: u32,
    pub argon_t: u32,
    pub argon_p: u32,
    pub chunk_plain: u32,
}

enum Node {
    Dir { rel: String },
    File { rel: String, path: PathBuf },
}

struct Partial {
    path: PathBuf,
    keep: bool,
}

impl Drop for Partial {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct Restoring {
    path: PathBuf,
    keep: bool,
}

impl Drop for Restoring {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub fn lock_folder(
    src: &Path,
    password: &str,
    options: &LockOptions,
    mut progress: impl FnMut(Progress),
) -> Result<LockResult, Error> {
    options.validate()?;
    check_password(password)?;
    let src = anchor_existing(src)?;
    ensure_real_dir(&src)?;

    let folder_name = src
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| message("文件夹名无法用 UTF-8 表示"))?;
    let parent = src.parent().ok_or_else(|| message("不能加密磁盘根目录"))?;
    let vault_path = parent.join(format!("{folder_name}.flock"));
    let partial_path = parent.join(format!(".{folder_name}.flock.partial"));
    if vault_path.starts_with(&src) {
        return Err(message("保险箱不能创建在被加密的文件夹里面"));
    }
    if fs::symlink_metadata(&vault_path).is_ok() {
        return Err(message(format!("锁定入口已存在：{}", display_path(&vault_path))));
    }

    progress(Progress {
        phase: "scan",
        done: 0,
        total: 0,
        current: String::new(),
    });
    let mut nodes = Vec::new();
    let mut seen = 0u64;
    walk(&src, &src, &mut nodes, &mut progress, &mut seen)?;
    let total_files = nodes.iter().filter(|node| matches!(node, Node::File { .. })).count() as u64;

    progress(Progress {
        phase: "kdf",
        done: 0,
        total: 0,
        current: "正在派生密钥".into(),
    });
    let master = Zeroizing::new(random_array::<32>());
    let recovery = Zeroizing::new(random_array::<32>());
    let salt = random_array::<16>();
    let kek = Zeroizing::new(derive_kek(
        password.as_bytes(),
        &salt,
        options.argon_m_kib,
        options.argon_t,
        options.argon_p,
    )?);
    let pw_nonce = random_array::<12>();
    let rk_nonce = random_array::<12>();
    let pw_wrapped = wrap_master(&kek, &pw_nonce, &master, false)?;
    let rk_wrapped = wrap_master(&recovery, &rk_nonce, &master, true)?;
    let mut recovery_key = Zeroizing::new(folderlock_crypto::format_recovery_key(&recovery));

    remove_work_path(&partial_path)?;
    let mut partial = Partial {
        path: partial_path.clone(),
        keep: false,
    };
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial_path)
        .map_err(|err| io_msg(&partial_path, err))?;
    let mut out = OutFile {
        file: BufWriter::new(file),
        pos: 0,
    };
    out.write_all(&[0u8; HEADER_LEN])?;
    let mut nonces = NonceGen::new();
    let mut entries = Vec::with_capacity(nodes.len());
    let mut done = 0u64;
    let chunk = u64::from(options.chunk_plain);

    for node in &nodes {
        match node {
            Node::Dir { rel } => entries.push(Entry {
                path: rel.clone(),
                dir: true,
                offset: 0,
                length: 0,
                plain_len: 0,
            }),
            Node::File { rel, path } => {
                done += 1;
                progress(Progress {
                    phase: "encrypt",
                    done,
                    total: total_files,
                    current: rel.clone(),
                });
                let mut input = File::open(path).map_err(|err| io_msg(path, err))?;
                let (offset, length, plain_len) = encrypt_file(&mut input, &mut out, &master, rel, chunk, &mut nonces)?;
                entries.push(Entry {
                    path: rel.clone(),
                    dir: false,
                    offset,
                    length,
                    plain_len,
                });
            }
        }
    }

    let manifest = Manifest { v: 1, entries };
    validate_manifest(&manifest, HEADER_LEN as u64, out.pos, chunk)?;
    let manifest_nonce = nonces.next();
    let manifest_ct = seal_manifest(&master, &manifest_nonce, &manifest)?;
    let manifest_offset = out.pos;
    out.write_all(&manifest_ct)?;
    let header = Header {
        argon_m_kib: options.argon_m_kib,
        argon_t: options.argon_t,
        argon_p: options.argon_p,
        chunk_plain: options.chunk_plain,
        salt,
        pw_nonce,
        pw_wrapped,
        rk_nonce,
        rk_wrapped,
        manifest_nonce,
        manifest_offset,
        manifest_len: manifest_ct.len() as u64,
        data_offset: HEADER_LEN as u64,
    };
    let bytes = header.serialize()?;
    out.finish_header(&bytes)?;
    drop(out);

    fs::rename(&partial_path, &vault_path).map_err(|err| io_msg(&vault_path, err))?;
    partial.keep = true;
    notify_parent(&vault_path);

    let wipe_error = match wipe_committed(&src, total_files, &mut progress) {
        Ok(()) => None,
        Err(err) => Some(err.to_string()),
    };
    notify_parent(&src);

    Ok(LockResult {
        vault: display_path(&vault_path),
        recovery_key: std::mem::take(&mut *recovery_key),
        wipe_error,
    })
}

fn wipe_committed(src: &Path, total_files: u64, progress: &mut impl FnMut(Progress)) -> Result<(), Error> {
    let mut done = 0u64;
    wipe_tree(src, |_| {
        done += 1;
        progress(Progress {
            phase: "wipe",
            done,
            total: total_files,
            current: String::new(),
        });
    })
}

pub fn unlock_vault(
    vault: &Path,
    secret: &str,
    kind: SecretKind,
    mut progress: impl FnMut(Progress),
) -> Result<UnlockResult, Error> {
    let vault = anchor_existing(vault)?;
    let meta = fs::symlink_metadata(&vault).map_err(|err| io_msg(&vault, err))?;
    if is_reparse(&meta) || !meta.is_file() {
        return Err(message("这不是保险箱文件"));
    }
    let (header, file_len) = read_header(&vault)?;
    header.validate_bounds(file_len)?;

    progress(Progress {
        phase: "kdf",
        done: 0,
        total: 0,
        current: "正在派生密钥".into(),
    });
    let master = Zeroizing::new(unwrap_secret(&header, secret, kind)?);

    let mut file = File::open(&vault).map_err(|err| io_msg(&vault, err))?;
    file.seek(SeekFrom::Start(header.manifest_offset))
        .map_err(|err| io_msg(&vault, err))?;
    let mut manifest_ct = vec![0u8; header.manifest_len as usize];
    file.read_exact(&mut manifest_ct).map_err(|err| io_msg(&vault, err))?;
    let manifest = open_manifest(&master, &header.manifest_nonce, &manifest_ct)?;
    let chunk = u64::from(header.chunk_plain);
    validate_manifest(&manifest, header.data_offset, header.manifest_offset, chunk)?;

    let file_name = vault
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| message("保险箱文件名无法用 UTF-8 表示"))?;
    let folder_name = strip_flock(file_name).ok_or_else(|| message("保险箱文件必须以 .flock 结尾"))?;
    let parent = vault.parent().ok_or_else(|| message("保险箱路径无效"))?;
    let folder = parent.join(folder_name);
    let temp = parent.join(format!(".{folder_name}.restoring"));
    if fs::symlink_metadata(&folder).is_ok() {
        return Err(message(format!("目标文件夹已存在：{}", display_path(&folder))));
    }
    remove_work_path(&temp)?;
    fs::create_dir(&temp).map_err(|err| io_msg(&temp, err))?;
    let mut restoring = Restoring {
        path: temp.clone(),
        keep: false,
    };

    let files: Vec<&Entry> = manifest.entries.iter().filter(|entry| !entry.dir).collect();
    let total = files.len() as u64;
    let mut dirs: Vec<&Entry> = manifest.entries.iter().filter(|entry| entry.dir).collect();
    dirs.sort_by_key(|entry| entry.path.len());
    for entry in dirs {
        let dest = join_rel(&temp, &entry.path)?;
        fs::create_dir_all(&dest).map_err(|err| io_msg(&dest, err))?;
    }
    for (index, entry) in files.iter().enumerate() {
        progress(Progress {
            phase: "decrypt",
            done: index as u64 + 1,
            total,
            current: entry.path.clone(),
        });
        let dest = join_rel(&temp, &entry.path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|err| io_msg(parent, err))?;
        }
        decrypt_entry(&mut file, entry, &dest, &master, chunk)?;
    }
    drop(file);

    fs::rename(&temp, &folder).map_err(|err| io_msg(&folder, err))?;
    restoring.keep = true;
    let remove_error = match fs::remove_file(&vault) {
        Ok(()) => None,
        Err(err) => Some(format!("文件夹已恢复，但保险箱文件没有删除：{}", io_msg(&vault, err))),
    };
    notify_parent(&folder);
    Ok(UnlockResult {
        folder: display_path(&folder),
        remove_error,
    })
}

pub fn inspect_vault(vault: &Path) -> Result<VaultInfo, Error> {
    let vault = anchor_existing(vault)?;
    let (header, bytes) = read_header(&vault)?;
    header.validate_bounds(bytes)?;
    Ok(VaultInfo {
        bytes,
        argon_m_kib: header.argon_m_kib,
        argon_t: header.argon_t,
        argon_p: header.argon_p,
        chunk_plain: header.chunk_plain,
    })
}

fn unwrap_secret(header: &Header, secret: &str, kind: SecretKind) -> Result<[u8; 32], Error> {
    match kind {
        SecretKind::Password => {
            check_password(secret)?;
            let kek = Zeroizing::new(derive_kek(
                secret.as_bytes(),
                &header.salt,
                header.argon_m_kib,
                header.argon_t,
                header.argon_p,
            )?);
            Ok(unwrap_master(&kek, &header.pw_nonce, &header.pw_wrapped, false)?)
        }
        SecretKind::RecoveryKey => {
            let recovery = Zeroizing::new(folderlock_crypto::parse_recovery_key(secret)?);
            Ok(unwrap_master(&recovery, &header.rk_nonce, &header.rk_wrapped, true)?)
        }
    }
}

fn read_header(path: &Path) -> Result<(Header, u64), Error> {
    let mut file = File::open(path).map_err(|err| io_msg(path, err))?;
    let file_len = file.metadata().map_err(|err| io_msg(path, err))?.len();
    if file_len < HEADER_LEN as u64 {
        return Err(message("文件太小，不是保险箱"));
    }
    let mut buf = [0u8; HEADER_LEN];
    file.read_exact(&mut buf).map_err(|err| io_msg(path, err))?;
    Ok((Header::parse(&buf)?, file_len))
}

fn encrypt_file(
    input: &mut File,
    out: &mut OutFile,
    key: &[u8; 32],
    rel: &str,
    chunk: u64,
    nonces: &mut NonceGen,
) -> Result<(u64, u64, u64), Error> {
    let offset = out.pos;
    let mut plain_len = 0u64;
    let mut index = 0u64;
    let mut buf = vec![0u8; chunk as usize];
    loop {
        let n = read_chunk(input, &mut buf).map_err(|err| message(err.to_string()))?;
        if n == 0 {
            break;
        }
        let nonce = nonces.next();
        let aad = chunk_aad(rel, index);
        let ciphertext = seal(key, &nonce, &buf[..n], &aad)?;
        out.write_all(&nonce)?;
        out.write_all(&ciphertext)?;
        plain_len += n as u64;
        index += 1;
        if (n as u64) < chunk {
            break;
        }
    }
    buf.zeroize();
    let length = out.pos - offset;
    if length != expected_payload_len(plain_len, chunk)? {
        return Err(message("内部错误：密文长度不一致"));
    }
    Ok((offset, length, plain_len))
}

fn decrypt_entry(src: &mut File, entry: &Entry, dest: &Path, key: &[u8; 32], chunk: u64) -> Result<(), Error> {
    if expected_payload_len(entry.plain_len, chunk)? != entry.length {
        return Err(message("清单中的文件长度不正确"));
    }
    let mut output = File::create(dest).map_err(|err| io_msg(dest, err))?;
    if entry.plain_len == 0 {
        output.sync_all().map_err(|err| io_msg(dest, err))?;
        return Ok(());
    }
    src.seek(SeekFrom::Start(entry.offset)).map_err(|err| io_msg(dest, err))?;
    let mut left = entry.plain_len;
    let mut index = 0u64;
    while left > 0 {
        let n = std::cmp::min(chunk, left);
        let mut nonce = [0u8; 12];
        src.read_exact(&mut nonce).map_err(|err| io_msg(dest, err))?;
        let mut ciphertext = vec![0u8; n as usize + 16];
        src.read_exact(&mut ciphertext).map_err(|err| io_msg(dest, err))?;
        let plain = open(key, &nonce, &ciphertext, &chunk_aad(&entry.path, index))?;
        if plain.len() as u64 != n {
            return Err(message("解密后的分块长度不正确"));
        }
        output.write_all(&plain).map_err(|err| io_msg(dest, err))?;
        ciphertext.zeroize();
        left -= n;
        index += 1;
    }
    output.sync_all().map_err(|err| io_msg(dest, err))?;
    Ok(())
}

fn read_chunk(input: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match input.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<Node>, progress: &mut impl FnMut(Progress), seen: &mut u64) -> Result<(), Error> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(|err| io_msg(dir, err))? {
        entries.push(entry.map_err(|err| io_msg(dir, err))?);
    }
    entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    for entry in entries {
        let path = entry.path();
        let meta = entry.metadata().map_err(|err| io_msg(&path, err))?;
        if is_reparse(&meta) {
            return Err(message(format!(
                "文件夹里有符号链接或联接，已取消加密：{}",
                display_path(&path)
            )));
        }
        let rel = rel_string(&path, base)?;
        *seen += 1;
        if *seen % 100 == 0 {
            progress(Progress {
                phase: "scan",
                done: *seen,
                total: 0,
                current: rel.clone(),
            });
        }
        if meta.is_dir() {
            out.push(Node::Dir { rel: rel.clone() });
            walk(&path, base, out, progress, seen)?;
        } else if meta.is_file() {
            out.push(Node::File { rel, path });
        } else {
            return Err(message(format!("不支持的文件类型：{}", display_path(&path))));
        }
    }
    Ok(())
}

fn rel_string(path: &Path, base: &Path) -> Result<String, Error> {
    let rel = path.strip_prefix(base).map_err(|_| message("内部错误：无法计算相对路径"))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or_else(|| message("路径包含无法用 UTF-8 表示的字符"))?;
                parts.push(part);
            }
            _ => return Err(message("路径包含不受支持的组成部分")),
        }
    }
    let joined = parts.join("/");
    validate_rel_path(&joined).map_err(|_| message(format!("这个路径不能放进保险箱：{joined}")))?;
    Ok(joined)
}

fn join_rel(root: &Path, rel: &str) -> Result<PathBuf, Error> {
    validate_rel_path(rel)?;
    let mut out = root.to_path_buf();
    for part in rel.split('/') {
        out.push(part);
    }
    if !out.starts_with(root) {
        return Err(message("清单路径逃出了目标文件夹"));
    }
    Ok(out)
}

fn ensure_real_dir(path: &Path) -> Result<(), Error> {
    let meta = fs::symlink_metadata(path).map_err(|err| io_msg(path, err))?;
    if is_reparse(&meta) {
        return Err(message("不能加密符号链接或联接"));
    }
    if !meta.is_dir() {
        return Err(message("请选择一个文件夹"));
    }
    Ok(())
}

fn anchor_existing(path: &Path) -> Result<PathBuf, Error> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|err| message(err.to_string()))?
            .join(path)
    };
    let name = path.file_name().ok_or_else(|| message("不能加密磁盘根目录"))?;
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).ok_or_else(|| message("不能加密磁盘根目录"))?;
    let parent = fs::canonicalize(parent).map_err(|err| io_msg(parent, err))?;
    Ok(parent.join(name))
}

fn strip_flock(name: &str) -> Option<&str> {
    let (base, ext) = name.rsplit_once('.')?;
    if ext.eq_ignore_ascii_case("flock") && !base.is_empty() {
        Some(base)
    } else {
        None
    }
}

struct OutFile {
    file: BufWriter<File>,
    pos: u64,
}

impl OutFile {
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.file.write_all(buf).map_err(|err| message(err.to_string()))?;
        self.pos = self.pos.checked_add(buf.len() as u64).ok_or_else(|| message("保险箱过大"))?;
        Ok(())
    }

    fn finish_header(&mut self, header: &[u8]) -> Result<(), Error> {
        self.file.flush().map_err(|err| message(err.to_string()))?;
        self.file.seek(SeekFrom::Start(0)).map_err(|err| message(err.to_string()))?;
        self.file.write_all(header).map_err(|err| message(err.to_string()))?;
        self.file.flush().map_err(|err| message(err.to_string()))?;
        self.file.get_ref().sync_all().map_err(|err| message(err.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
fn test_options() -> LockOptions {
    LockOptions {
        argon_m_kib: 32,
        argon_t: 1,
        argon_p: 1,
        chunk_plain: 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MIN_PASSWORD_CHARS;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("folderlock-{}-{}-{}", std::process::id(), n, random_array::<4>()[0]));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn noop(_: Progress) {}

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn lock_and_unlock_roundtrip() {
        let tmp = Tmp::new();
        let src = tmp.0.join("My.Docs");
        fs::create_dir_all(src.join("笔记")).unwrap();
        fs::create_dir_all(src.join("empty")).unwrap();
        let marker = b"PLAINTEXT-MARKER-7f3c9a";
        write(&src.join("笔记").join("文档.txt"), marker);
        write(&src.join("empty-file"), b"");
        write(&src.join("exact.bin"), &[7u8; 64]);
        let mut wide_bytes = vec![9u8; 65];
        wide_bytes.extend_from_slice(&[0, 1, 2, 255]);
        write(&src.join("wide.bin"), &wide_bytes);

        let password = "correct horse";
        let locked = lock_folder(&src, password, &test_options(), noop).unwrap();
        assert!(locked.wipe_error.is_none(), "{:?}", locked.wipe_error);
        assert!(!src.exists());
        let vault = PathBuf::from(&locked.vault);
        assert!(vault.is_file(), "{}", locked.vault);
        assert!(locked.recovery_key.starts_with("FLRK-"));

        let raw = fs::read(&vault).unwrap();
        assert!(!raw.windows(marker.len()).any(|w| w == marker));
        assert!(!raw.windows("文档.txt".len()).any(|w| w == "文档.txt".as_bytes()));
        assert!(!raw.windows(locked.recovery_key.len()).any(|w| w == locked.recovery_key.as_bytes()));

        let wrong = unlock_vault(&vault, "wrong-password", SecretKind::Password, noop);
        assert!(wrong.is_err());
        assert!(!tmp.0.join("My.Docs").exists());
        assert!(vault.is_file());

        let short = "a".repeat(MIN_PASSWORD_CHARS - 1);
        assert!(unlock_vault(&vault, &short, SecretKind::Password, noop).is_err());

        let restored = unlock_vault(&vault, &locked.recovery_key, SecretKind::RecoveryKey, noop).unwrap();
        assert!(restored.remove_error.is_none(), "{:?}", restored.remove_error);
        assert!(!vault.exists());
        let back = tmp.0.join("My.Docs");
        assert_eq!(fs::read(back.join("笔记").join("文档.txt")).unwrap(), marker);
        assert_eq!(fs::read(back.join("empty-file")).unwrap(), b"");
        assert_eq!(fs::read(back.join("exact.bin")).unwrap(), vec![7u8; 64]);
        assert!(back.join("empty").is_dir());
        let wide = fs::read(back.join("wide.bin")).unwrap();
        assert_eq!(wide.len(), 69);
        assert_eq!(&wide[..65], &[9u8; 65]);
        assert_eq!(&wide[65..], &[0, 1, 2, 255]);
    }

    #[test]
    fn refuses_to_overwrite_existing_folder() {
        let tmp = Tmp::new();
        let src = tmp.0.join("Box");
        fs::create_dir(&src).unwrap();
        write(&src.join("a.txt"), b"data");
        let locked = lock_folder(&src, "password12", &test_options(), noop).unwrap();
        fs::create_dir(tmp.0.join("Box")).unwrap();
        let err = unlock_vault(Path::new(&locked.vault), "password12", SecretKind::Password, noop).unwrap_err();
        assert!(err.to_string().contains("已存在"));
        assert!(Path::new(&locked.vault).is_file());
    }

    #[test]
    fn tamper_does_not_leave_a_folder() {
        let tmp = Tmp::new();
        let src = tmp.0.join("Notes");
        fs::create_dir(&src).unwrap();
        write(&src.join("a.txt"), b"abcdefghijklmnop");
        let locked = lock_folder(&src, "password12", &test_options(), noop).unwrap();
        let vault = PathBuf::from(&locked.vault);
        let mut raw = fs::read(&vault).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x5a;
        fs::write(&vault, &raw).unwrap();
        assert!(unlock_vault(&vault, "password12", SecretKind::Password, noop).is_err());
        assert!(!tmp.0.join("Notes").exists());
        assert!(!tmp.0.join(".Notes.restoring").exists());
    }

    #[test]
    fn production_defaults_are_strong() {
        let options = LockOptions::default();
        assert!(options.argon_m_kib >= 64 * 1024);
        assert!(options.argon_t >= 3);
        assert_eq!(options.argon_p, 1);
        assert_eq!(options.chunk_plain, 1024 * 1024);
    }

    #[test]
    fn dotted_name_and_password_unlock() {
        let tmp = Tmp::new();
        let src = tmp.0.join("quarter.report");
        fs::create_dir(&src).unwrap();
        write(&src.join("n.txt"), b"2026");
        let locked = lock_folder(&src, "quarter-report", &test_options(), noop).unwrap();
        let restored = unlock_vault(Path::new(&locked.vault), "quarter-report", SecretKind::Password, noop).unwrap();
        assert!(restored.folder.ends_with("quarter.report"));
        assert_eq!(fs::read(tmp.0.join("quarter.report").join("n.txt")).unwrap(), b"2026");
    }
}

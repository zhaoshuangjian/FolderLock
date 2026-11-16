# FolderLock

Windows、macOS 和 Linux 上的文件夹加密工具。在文件管理器里右键文件夹即可加密；原位置留下一个 `.flock` 锁定入口，双击并输入密码后恢复成原来的文件夹。同一份 `.flock` 可以拷到另一台电脑，用原来的密码或恢复密钥解开。

## 实现方案

加密对象是整个文件夹，不是挂载一个虚拟磁盘。完成后明文文件夹会被覆盖删除，旁边留下同名的 `文件夹.flock`。系统若隐藏了已知扩展名，它仍显示原来的名字，双击由本程序打开。

密钥分成三层：

1. 随机生成 256 位主密钥，文件内容只使用这把密钥。
2. 密码用 Argon2id（64 MiB 内存、3 次迭代、并行度 1）派生包装密钥，再用 AES-256-GCM 包住主密钥。
3. 另外生成一把独立的 256 位恢复密钥，用同样方式再包一份主密钥。忘记密码时，恢复密钥可以单独解开保险箱。它和密码等价，不是第二因素。

文件名不出现在磁盘上。相对路径写进一份清单，清单本身用主密钥做 AES-256-GCM。文件内容按 1 MiB 分块加密，每块使用独立计数器 nonce，并把路径和块序号放进附加认证数据，避免密文被调包或换序。

保险箱是单个文件，布局固定为 512 字节文件头、加密数据、加密清单。文件头里记录 Argon2 参数、两份包装后的主密钥，以及清单位置。口令错误或文件被改动时，GCM 校验失败，不会写出半个文件夹。

右键菜单和双击解锁按当前用户安装，不需要管理员：

- Windows：写入 `HKCU\Software\Classes`。Windows 11 的新版菜单里，加密命令在「显示更多选项」中。
- macOS：在 `~/Library/Services` 安装访达快速操作，并注册一个当前用户的 FolderLock 应用来打开 `.flock`。
- Linux：安装 `.desktop` 和 MIME 类型，供双击打开。KDE Dolphin、XFCE Thunar 有右键项；GNOME 和 Cinnamon 在右键的「脚本」菜单里。

## 构建

需要 Rust 1.77 或更新版本。图形界面在 Windows 上使用 WebView2，在 macOS 上使用系统 WebKit，在 Linux 上使用 WebKitGTK。

```powershell
cargo test
cargo build --release
```

如果链接图形程序时提示找不到 `vswhom_find_visual_studio_and_windows_sdk`，把环境变量 `AR` 指到本机 Visual Studio 的 `lib.exe`（`VC\Tools\MSVC\...\bin\Hostx64\x64\lib.exe`）后再编译。

产物：

- `target\release\folderlock`（Windows 上是 `folderlock.exe`）：图形界面，也是右键菜单和双击锁定入口时启动的程序
- `target\release\folderlock-cli`（Windows 上是 `folderlock-cli.exe`）：命令行

开发界面热重载：

```powershell
cargo install tauri-cli --version "^2"
cargo tauri dev
```

## 使用

图形界面可以加密、解锁、复制恢复密钥，以及注册或移除右键菜单。

```powershell
folderlock-cli lock D:\私人
folderlock-cli unlock D:\私人.flock
folderlock-cli unlock D:\私人.flock --recovery
folderlock-cli info D:\私人.flock
folderlock-cli register --exe target\release\folderlock
folderlock-cli unregister
```

交互模式下密码不回显，并要求输入两次。脚本可以用 `--password-stdin`，或 `--password-env` 读取 `FOLDERLOCK_PASSWORD`。恢复密钥在加密成功时只打印一次。

退出码：`0` 成功，`1` 失败，`3` 表示保险箱或文件夹已经写好，但旧文件没有删干净。

## 限制

- 解锁后就是普通文件夹，关机前需要再次加密。
- 覆盖删除只能尽力而为。固态硬盘、卷影副本和云盘历史版本仍可能留下旧数据。
- 不跟随符号链接和目录联接，避免加密或删除链接外面的文件。
- 加密过程需要大约一份文件夹大小的额外磁盘空间。
- 知道文件格式的人可以从分块长度估计单个文件的大小，但看不到文件名和内容。

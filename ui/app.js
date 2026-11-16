const phases = {
  scan: "正在扫描",
  kdf: "正在派生密钥",
  encrypt: "正在加密",
  wipe: "正在清除明文",
  decrypt: "正在解密",
  restore: "正在写回",
};

const state = {
  recovery: false,
  shell: false,
  busy: false,
  folder: "",
};

function tauriApi() {
  if (!window.__TAURI__ || !window.__TAURI__.core) {
    throw new Error("请在 FolderLock 窗口里打开这个页面");
  }
  return window.__TAURI__;
}

function invoke(command, args) {
  return tauriApi().core.invoke(command, args);
}

function $(id) {
  return document.getElementById(id);
}

function show(view) {
  for (const id of ["view-home", "view-lock", "view-unlock", "view-recovery", "view-done"]) {
    $(id).hidden = id !== view;
  }
  if (view !== "view-lock" && view !== "view-unlock") {
    $("progress").hidden = true;
  }
}

function banner(text, warn) {
  const el = $("banner");
  if (!text) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  el.hidden = false;
  el.textContent = text;
  el.classList.toggle("warn", Boolean(warn));
}

function setBusy(busy) {
  state.busy = busy;
  for (const id of ["lock-submit", "unlock-submit", "browse-folder", "browse-vault", "shell-toggle", "go-lock", "go-unlock"]) {
    $(id).disabled = busy;
  }
  $("lock-password").disabled = busy;
  $("lock-confirm").disabled = busy;
  $("unlock-secret").disabled = busy;
}

function onProgress(progress) {
  const label = phases[progress.phase] || "处理中";
  const detail = progress.total > 0 ? `${label} ${progress.done}/${progress.total}` : label;
  const name = progress.current ? ` ${progress.current}` : "";
  $("progress").hidden = false;
  $("progress-text").textContent = `${detail}${name}`;
  const ratio = progress.total > 0 ? Math.min(100, Math.round((progress.done / progress.total) * 100)) : progress.phase === "kdf" ? 12 : 8;
  $("progress-fill").style.width = `${ratio}%`;
}

async function refreshShell() {
  try {
    const info = await invoke("shell_status");
    state.shell = Boolean(info.registered);
    $("shell-title").textContent = info.title;
    $("shell-text").textContent = info.detail;
    $("shell-hint").textContent = info.hint;
  } catch (err) {
    state.shell = false;
    banner(String(err));
  }
  $("shell-toggle").textContent = state.shell ? "移除" : "注册";
}

function setUnlockMode(recovery) {
  state.recovery = recovery;
  $("mode-password").classList.toggle("active", !recovery);
  $("mode-recovery").classList.toggle("active", recovery);
  $("mode-password").setAttribute("aria-selected", String(!recovery));
  $("mode-recovery").setAttribute("aria-selected", String(recovery));
  $("secret-label").textContent = recovery ? "恢复密钥" : "密码";
  const input = $("unlock-secret");
  input.type = recovery ? "text" : "password";
  input.placeholder = recovery ? "FLRK-...." : "";
  input.value = "";
}

async function inspect(path) {
  $("vault-meta").textContent = "";
  if (!path) return;
  try {
    const info = await invoke("inspect_vault", { path });
    const memory = Math.round(info.argon_m_kib / 1024);
    $("vault-meta").textContent = `保险箱 ${info.bytes} 字节 · Argon2id ${memory} MiB`;
  } catch (err) {
    $("vault-meta").textContent = String(err);
  }
}

async function init() {
  try {
    const launch = await invoke("launch_context");
    await tauriApi().event.listen("progress", (event) => onProgress(event.payload));
    await refreshShell();
    if (launch.mode === "lock") {
      $("lock-path").value = launch.path || "";
      show("view-lock");
    } else if (launch.mode === "unlock") {
      $("unlock-path").value = launch.path || "";
      show("view-unlock");
      inspect(launch.path);
    } else {
      show("view-home");
    }
  } catch (err) {
    banner(String(err));
  }
}

$("go-lock").addEventListener("click", () => {
  banner("");
  show("view-lock");
});
$("go-unlock").addEventListener("click", () => {
  banner("");
  show("view-unlock");
});
$("lock-back").addEventListener("click", () => {
  if (!state.busy) show("view-home");
});
$("unlock-back").addEventListener("click", () => {
  if (!state.busy) show("view-home");
});

$("browse-folder").addEventListener("click", async () => {
  banner("");
  const path = await invoke("pick_folder");
  if (path) $("lock-path").value = path;
});

$("browse-vault").addEventListener("click", async () => {
  banner("");
  const path = await invoke("pick_vault");
  if (path) {
    $("unlock-path").value = path;
    inspect(path);
  }
});

$("mode-password").addEventListener("click", () => setUnlockMode(false));
$("mode-recovery").addEventListener("click", () => setUnlockMode(true));

$("shell-toggle").addEventListener("click", async () => {
  banner("");
  setBusy(true);
  try {
    if (state.shell) await invoke("unregister_shell");
    else await invoke("register_shell");
    await refreshShell();
  } catch (err) {
    banner(String(err));
  } finally {
    setBusy(false);
  }
});

$("lock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  banner("");
  const path = $("lock-path").value.trim();
  const password = $("lock-password").value;
  const confirm = $("lock-confirm").value;
  if (!path) {
    banner("先选择一个文件夹");
    return;
  }
  setBusy(true);
  onProgress({ phase: "kdf", done: 0, total: 0, current: "" });
  try {
    const result = await invoke("lock_folder", { path, password, confirm });
    $("lock-password").value = "";
    $("lock-confirm").value = "";
    $("recovery-key").value = result.recovery_key;
    $("saved-key").checked = false;
    $("recovery-done").disabled = true;
    const wiped = result.wipe_error
      ? `保险箱已经写好，但原文件夹还在：${result.wipe_error}`
      : "原文件夹已经清除。";
    $("recovery-lead").textContent = `锁定入口：${result.vault}。${wiped}忘记密码时，只能靠下面这把恢复密钥打开它。`;
    banner(result.wipe_error || "", true);
    show("view-recovery");
  } catch (err) {
    banner(String(err));
  } finally {
    setBusy(false);
    $("progress").hidden = true;
  }
});

$("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  banner("");
  const path = $("unlock-path").value.trim();
  const secret = $("unlock-secret").value;
  if (!path) {
    banner("先选择一个 .flock 保险箱");
    return;
  }
  setBusy(true);
  onProgress({ phase: "kdf", done: 0, total: 0, current: "" });
  try {
    const result = await invoke("unlock_vault", { path, secret, recovery: state.recovery });
    $("unlock-secret").value = "";
    state.folder = result.folder;
    $("done-title").textContent = "已解锁";
    $("done-lead").textContent = result.remove_error
      ? `${result.folder}。${result.remove_error}`
      : `文件夹已恢复到 ${result.folder}`;
    banner(result.remove_error || "", true);
    show("view-done");
  } catch (err) {
    banner(String(err));
  } finally {
    setBusy(false);
    $("progress").hidden = true;
  }
});

$("copy-key").addEventListener("click", async () => {
  try {
    await invoke("copy_text", { text: $("recovery-key").value });
    $("copy-key").textContent = "已复制";
  } catch (err) {
    banner(String(err));
  }
});

$("saved-key").addEventListener("change", () => {
  $("recovery-done").disabled = !$("saved-key").checked;
});

$("recovery-done").addEventListener("click", () => {
  $("recovery-key").value = "";
  banner("");
  show("view-home");
  refreshShell();
});

$("open-folder").addEventListener("click", async () => {
  if (!state.folder) return;
  try {
    await invoke("open_path", { path: state.folder });
  } catch (err) {
    banner(String(err));
  }
});

$("done-home").addEventListener("click", () => {
  banner("");
  show("view-home");
});

init();

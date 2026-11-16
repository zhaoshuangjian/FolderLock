//! 三个系统共用的集成文件内容。安装动作在 `shell` 模块里按系统执行。

pub const BUNDLE_ID: &str = "app.folderlock.desktop";
pub const MIME: &str = "application/x-folderlock";
const THUNAR_BEGIN: &str = "<!-- folderlock-begin -->";
const THUNAR_END: &str = "<!-- folderlock-end -->";

pub fn bash_single_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn desktop_file(exe: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Version=1.0\n\
         Type=Application\n\
         Name=FolderLock\n\
         Comment=解锁 FolderLock 保险箱\n\
         Exec={exe} unlock %f\n\
         MimeType={MIME};\n\
         Terminal=false\n\
         NoDisplay=false\n\
         Categories=Utility;Security;\n\
         StartupNotify=true\n",
        exe = bash_single_quote(exe)
    )
}

pub fn mime_xml() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">\n\
       <mime-type type=\"application/x-folderlock\">\n\
         <comment>FolderLock 保险箱</comment>\n\
         <glob pattern=\"*.flock\"/>\n\
         <glob pattern=\"*.FLOCK\"/>\n\
       </mime-type>\n\
     </mime-info>\n"
}

pub fn file_manager_script(exe: &str) -> String {
    let exe = bash_single_quote(exe);
    format!(
        "#!/bin/sh\n\
         # FolderLock\n\
         lock()\n\
         {{\n\
           [ -n \"$1\" ] && {exe} lock \"$1\"\n\
         }}\n\
         if [ -n \"$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\" ]; then\n\
           printf '%s\\n' \"$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\" | while IFS= read -r f; do lock \"$f\"; done\n\
         elif [ -n \"$NEMO_SCRIPT_SELECTED_FILE_PATHS\" ]; then\n\
           printf '%s\\n' \"$NEMO_SCRIPT_SELECTED_FILE_PATHS\" | while IFS= read -r f; do lock \"$f\"; done\n\
         elif [ -n \"$CAJA_SCRIPT_SELECTED_FILE_PATHS\" ]; then\n\
           printf '%s\\n' \"$CAJA_SCRIPT_SELECTED_FILE_PATHS\" | while IFS= read -r f; do lock \"$f\"; done\n\
         else\n\
           for f in \"$@\"; do lock \"$f\"; done\n\
         fi\n"
    )
}

pub fn dolphin_service(exe: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Service\n\
         MimeType=inode/directory;\n\
         Actions=folderlock-lock\n\
         X-KDE-Priority=TopLevel\n\
         X-KDE-StartupNotify=false\n\
         \n\
         [Desktop Action folderlock-lock]\n\
         Name=使用 FolderLock 加密\n\
         Exec={exe} lock %f\n",
        exe = bash_single_quote(exe)
    )
}

pub fn thunar_action(exe: &str) -> String {
    format!(
        "<action>\n\
         \t<icon>folder-locked</icon>\n\
         \t<name>使用 FolderLock 加密</name>\n\
         \t<unique-id>folderlock-encrypt</unique-id>\n\
         \t<command>{} lock %f</command>\n\
         \t<description>用密码加密这个文件夹</description>\n\
         \t<patterns>*</patterns>\n\
         \t<directories/>\n\
         </action>",
        xml_escape(&bash_single_quote(exe))
    )
}

pub fn upsert_thunar(existing: Option<&str>, exe: &str) -> String {
    let block = format!("{THUNAR_BEGIN}\n{}\n{THUNAR_END}", thunar_action(exe));
    match existing {
        None => format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<actions>\n{block}\n</actions>\n"),
        Some(text) => insert_before_end_tag(&remove_marked_block(text, THUNAR_BEGIN, THUNAR_END), "</actions>", &block),
    }
}

pub fn remove_thunar(existing: &str) -> String {
    remove_marked_block(existing, THUNAR_BEGIN, THUNAR_END)
}

pub fn thunar_has_other_actions(text: &str) -> bool {
    let stripped = remove_thunar(text);
    stripped.contains("<action>") || stripped.contains("<action ")
}

pub fn applescript(exe: &str) -> String {
    let quoted = applescript_string(exe);
    format!(
        "on open theFiles\n\
         \trepeat with f in theFiles\n\
         \t\tset p to POSIX path of f\n\
         \t\tdo shell script quoted form of {quoted} & \" unlock \" & quoted form of p & \" >/dev/null 2>&1 &\"\n\
         \tend repeat\n\
         end open\n\
         \n\
         on run\n\
         \tdo shell script quoted form of {quoted} & \" >/dev/null 2>&1 &\"\n\
         end run\n"
    )
}

pub fn macos_app_plist(executable: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>CFBundleExecutable</key>\n\
         \t<string>{}</string>\n\
         \t<key>CFBundleIdentifier</key>\n\
         \t<string>{BUNDLE_ID}</string>\n\
         \t<key>CFBundleName</key>\n\
         \t<string>FolderLock</string>\n\
         \t<key>CFBundleDisplayName</key>\n\
         \t<string>FolderLock</string>\n\
         \t<key>CFBundlePackageType</key>\n\
         \t<string>APPL</string>\n\
         \t<key>CFBundleShortVersionString</key>\n\
         \t<string>0.1.0</string>\n\
         \t<key>CFBundleVersion</key>\n\
         \t<string>0.1.0</string>\n\
         \t<key>CFBundleInfoDictionaryVersion</key>\n\
         \t<string>6.0</string>\n\
         \t<key>LSMinimumSystemVersion</key>\n\
         \t<string>11.0</string>\n\
         \t<key>NSHighResolutionCapable</key>\n\
         \t<true/>\n\
         \t<key>UTExportedTypeDeclarations</key>\n\
         \t<array>\n\
         \t\t<dict>\n\
         \t\t\t<key>UTTypeIdentifier</key>\n\
         \t\t\t<string>app.folderlock.vault</string>\n\
         \t\t\t<key>UTTypeDescription</key>\n\
         \t\t\t<string>FolderLock 保险箱</string>\n\
         \t\t\t<key>UTTypeConformsTo</key>\n\
         \t\t\t<array><string>public.data</string></array>\n\
         \t\t\t<key>UTTypeTagSpecification</key>\n\
         \t\t\t<dict>\n\
         \t\t\t\t<key>public.filename-extension</key>\n\
         \t\t\t\t<array><string>flock</string></array>\n\
         \t\t\t</dict>\n\
         \t\t</dict>\n\
         \t</array>\n\
         \t<key>CFBundleDocumentTypes</key>\n\
         \t<array>\n\
         \t\t<dict>\n\
         \t\t\t<key>CFBundleTypeName</key>\n\
         \t\t\t<string>FolderLock 保险箱</string>\n\
         \t\t\t<key>CFBundleTypeRole</key>\n\
         \t\t\t<string>Viewer</string>\n\
         \t\t\t<key>LSHandlerRank</key>\n\
         \t\t\t<string>Owner</string>\n\
         \t\t\t<key>LSItemContentTypes</key>\n\
         \t\t\t<array><string>app.folderlock.vault</string></array>\n\
         \t\t\t<key>CFBundleTypeExtensions</key>\n\
         \t\t\t<array><string>flock</string></array>\n\
         \t\t</dict>\n\
         \t</array>\n\
         </dict>\n\
         </plist>\n",
        xml_escape(executable)
    )
}

pub fn macos_service_info() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
     <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
     <plist version=\"1.0\">\n\
     <dict>\n\
     \t<key>NSServices</key>\n\
     \t<array>\n\
     \t\t<dict>\n\
     \t\t\t<key>NSMenuItem</key>\n\
     \t\t\t<dict><key>default</key><string>使用 FolderLock 加密</string></dict>\n\
     \t\t\t<key>NSMessage</key>\n\
     \t\t\t<string>runWorkflowAsService</string>\n\
     \t\t\t<key>NSRequiredContext</key>\n\
     \t\t\t<dict>\n\
     \t\t\t\t<key>NSApplicationIdentifier</key>\n\
     \t\t\t\t<string>com.apple.finder</string>\n\
     \t\t\t</dict>\n\
     \t\t\t<key>NSSendFileTypes</key>\n\
     \t\t\t<array><string>public.folder</string></array>\n\
     \t\t</dict>\n\
     \t</array>\n\
     </dict>\n\
     </plist>\n"
}

pub fn macos_service_workflow(exe: &str) -> String {
    let script = xml_escape(&format!("for f in \"$@\"; do {} lock \"$f\"; done\n", bash_single_quote(exe)));
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>AMApplicationBuild</key><string>523</string>\n\
         \t<key>AMApplicationVersion</key><string>2.10</string>\n\
         \t<key>AMDocumentVersion</key><string>2</string>\n\
         \t<key>actions</key>\n\
         \t<array>\n\
         \t\t<dict>\n\
         \t\t\t<key>action</key>\n\
         \t\t\t<dict>\n\
         \t\t\t\t<key>AMAccepts</key>\n\
         \t\t\t\t<dict>\n\
         \t\t\t\t\t<key>Container</key><string>List</string>\n\
         \t\t\t\t\t<key>Optional</key><true/>\n\
         \t\t\t\t\t<key>Types</key><array><string>com.apple.cocoa.string</string></array>\n\
         \t\t\t\t</dict>\n\
         \t\t\t\t<key>AMActionVersion</key><string>2.0.3</string>\n\
         \t\t\t\t<key>AMApplication</key><array><string>Automator</string></array>\n\
         \t\t\t\t<key>AMProvides</key>\n\
         \t\t\t\t<dict>\n\
         \t\t\t\t\t<key>Container</key><string>List</string>\n\
         \t\t\t\t\t<key>Types</key><array><string>com.apple.cocoa.string</string></array>\n\
         \t\t\t\t</dict>\n\
         \t\t\t\t<key>ActionBundlePath</key><string>/System/Library/Automator/Run Shell Script.action</string>\n\
         \t\t\t\t<key>ActionName</key><string>Run Shell Script</string>\n\
         \t\t\t\t<key>ActionParameters</key>\n\
         \t\t\t\t<dict>\n\
         \t\t\t\t\t<key>COMMAND_STRING</key><string>{script}</string>\n\
         \t\t\t\t\t<key>CheckedForUserDefaultShell</key><true/>\n\
         \t\t\t\t\t<key>inputMethod</key><integer>1</integer>\n\
         \t\t\t\t\t<key>shell</key><string>/bin/bash</string>\n\
         \t\t\t\t\t<key>source</key><string></string>\n\
         \t\t\t\t</dict>\n\
         \t\t\t\t<key>BundleIdentifier</key><string>com.apple.RunShellScript</string>\n\
         \t\t\t\t<key>CFBundleVersion</key><string>2.0.3</string>\n\
         \t\t\t\t<key>CanShowSelectedItemsWhenRun</key><false/>\n\
         \t\t\t\t<key>CanShowWhenRun</key><true/>\n\
         \t\t\t\t<key>Class Name</key><string>RunShellScriptAction</string>\n\
         \t\t\t\t<key>InputUUID</key><string>A1B2C3D4-1111-4111-8111-111111111111</string>\n\
         \t\t\t\t<key>OutputUUID</key><string>B2C3D4E5-2222-4222-8222-222222222222</string>\n\
         \t\t\t\t<key>UUID</key><string>C3D4E5F6-3333-4333-8333-333333333333</string>\n\
         \t\t\t\t<key>isViewVisible</key><integer>0</integer>\n\
         \t\t\t</dict>\n\
         \t\t</dict>\n\
         \t</array>\n\
         \t<key>connectors</key><dict/>\n\
         \t<key>workflowMetaData</key>\n\
         \t<dict>\n\
         \t\t<key>serviceApplicationBundleIdentifier</key><string>com.apple.finder</string>\n\
         \t\t<key>serviceInputTypeIdentifier</key><string>com.apple.Automator.fileSystemObject</string>\n\
         \t\t<key>serviceOutputTypeIdentifier</key><string>com.apple.Automator.nothing</string>\n\
         \t\t<key>serviceProcessesInput</key><false/>\n\
         \t\t<key>workflowTypeIdentifier</key><string>com.apple.Automator.servicesMenu</string>\n\
         \t</dict>\n\
         </dict>\n\
         </plist>\n"
    )
}

pub fn upsert_launch_services(xml: &str, bundle_id: &str) -> String {
    let handler = format!(
        "<dict>\n\
         \t<key>LSHandlerContentTag</key>\n\
         \t<string>flock</string>\n\
         \t<key>LSHandlerContentTagClass</key>\n\
         \t<string>public.filename-extension</string>\n\
         \t<key>LSHandlerRoleAll</key>\n\
         \t<string>{}</string>\n\
         </dict>",
        xml_escape(bundle_id)
    );
    if xml.trim().is_empty() {
        return launch_services_plist(&handler);
    }
    let Some((prefix, inner, suffix)) = split_handlers_array(xml) else {
        return insert_before_end_tag(xml, "</dict>", &format!("<key>LSHandlers</key>\n<array>\n{handler}\n</array>"));
    };
    let kept: Vec<&str> = top_level_dicts(inner)
        .into_iter()
        .filter(|dict| !is_flock_handler(dict))
        .collect();
    let mut body = String::new();
    for dict in kept {
        body.push_str(dict.trim());
        body.push('\n');
    }
    body.push_str(&handler);
    body.push('\n');
    format!("{prefix}{body}{suffix}")
}

pub fn remove_launch_services_flock(xml: &str) -> String {
    let Some((prefix, inner, suffix)) = split_handlers_array(xml) else {
        return xml.to_string();
    };
    let kept: Vec<&str> = top_level_dicts(inner)
        .into_iter()
        .filter(|dict| !is_flock_handler(dict))
        .collect();
    let mut body = String::new();
    for dict in kept {
        body.push_str(dict.trim());
        body.push('\n');
    }
    format!("{prefix}{body}{suffix}")
}

fn launch_services_plist(handler: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         <key>LSHandlers</key>\n\
         <array>\n\
         {handler}\n\
         </array>\n\
         </dict>\n\
         </plist>\n"
    )
}

fn applescript_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn insert_before_end_tag(text: &str, end_tag: &str, block: &str) -> String {
    let Some(index) = text.rfind(end_tag) else {
        return format!("{text}\n{block}\n");
    };
    format!("{}{}\n{}", &text[..index], block, &text[index..])
}

fn remove_marked_block(text: &str, begin: &str, end: &str) -> String {
    let Some(start) = text.find(begin) else {
        return text.to_string();
    };
    let Some(end_rel) = text[start..].find(end) else {
        return text.to_string();
    };
    let finish = start + end_rel + end.len();
    let mut out = String::new();
    out.push_str(&text[..start]);
    out.push_str(text[finish..].trim_start_matches('\n'));
    out
}

fn split_handlers_array(xml: &str) -> Option<(&str, &str, &str)> {
    let key = xml.find("<key>LSHandlers</key>")?;
    let array_rel = xml[key..].find("<array>")?;
    let inner_start = key + array_rel + "<array>".len();
    let array_end_rel = xml[inner_start..].find("</array>")?;
    let inner_end = inner_start + array_end_rel;
    Some((&xml[..inner_start], &xml[inner_start..inner_end], &xml[inner_end..]))
}

fn top_level_dicts(inner: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = inner;
    while let Some(start) = rest.find("<dict>") {
        let mut depth = 0;
        let mut pos = start;
        let bytes = rest.as_bytes();
        let mut found = false;
        while pos < bytes.len() {
            if rest[pos..].starts_with("<dict>") {
                depth += 1;
                pos += "<dict>".len();
            } else if rest[pos..].starts_with("</dict>") {
                depth -= 1;
                pos += "</dict>".len();
                if depth == 0 {
                    out.push(&rest[start..pos]);
                    rest = &rest[pos..];
                    found = true;
                    break;
                }
            } else {
                pos += 1;
            }
        }
        if !found {
            break;
        }
    }
    out
}

fn is_flock_handler(dict: &str) -> bool {
    dict.contains("<string>flock</string>") && dict.contains("public.filename-extension")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_files_point_at_the_program() {
        let exe = "/Applications/Folder Lock/folderlock";
        let desktop = desktop_file(exe);
        assert!(desktop.contains("'/Applications/Folder Lock/folderlock' unlock %f"));
        assert!(desktop.contains(MIME));
        assert!(mime_xml().contains("*.flock"));
        let script = file_manager_script(exe);
        assert!(script.contains("lock \"$f\""));
        assert!(script.contains("NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"));
        assert!(dolphin_service(exe).contains("inode/directory"));
        assert!(thunar_action(exe).contains("&apos;") || thunar_action(exe).contains("Folder Lock"));
        let apple = applescript(exe);
        assert!(apple.contains("unlock"));
        assert!(apple.contains("Folder Lock"));
        assert!(macos_app_plist("applet").contains("CFBundleExecutable"));
        assert!(macos_app_plist("applet").contains("<string>flock</string>"));
        assert!(macos_service_workflow(exe).contains("public.folder") || macos_service_info().contains("public.folder"));
        assert!(macos_service_workflow(exe).contains("lock"));
    }

    #[test]
    fn quotes_are_escaped() {
        let exe = "/tmp/it's\"folderlock";
        assert!(bash_single_quote(exe).starts_with('\''));
        assert!(applescript(exe).contains("unlock"));
        assert!(!desktop_file(exe).contains("it's\"folderlock' unlock"));
    }

    #[test]
    fn thunar_action_can_be_replaced_and_removed() {
        let first = upsert_thunar(Some("<actions>\n<action><name>Other</name></action>\n</actions>\n"), "/bin/old");
        assert!(first.contains("Other"));
        assert!(first.contains("/bin/old"));
        let second = upsert_thunar(Some(&first), "/bin/new");
        assert!(second.contains("/bin/new"));
        assert_eq!(second.matches("/bin/").count(), 1);
        let removed = remove_thunar(&second);
        assert!(!removed.contains("folderlock"));
        assert!(removed.contains("Other"));
        assert!(thunar_has_other_actions(&second));
    }

    #[test]
    fn launch_services_keeps_other_handlers() {
        let original = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>LSHandlers</key>
<array>
<dict>
<key>LSHandlerContentTag</key><string>txt</string>
<key>LSHandlerContentTagClass</key><string>public.filename-extension</string>
<key>LSHandlerRoleAll</key><string>com.apple.textedit</string>
</dict>
<dict>
<key>LSHandlerContentTag</key><string>flock</string>
<key>LSHandlerContentTagClass</key><string>public.filename-extension</string>
<key>LSHandlerRoleAll</key><string>old.app</string>
</dict>
</array>
</dict></plist>"#;
        let updated = upsert_launch_services(original, BUNDLE_ID);
        assert!(updated.contains("com.apple.textedit"));
        assert!(!updated.contains("old.app"));
        assert!(updated.contains(BUNDLE_ID));
        assert_eq!(updated.matches("<string>flock</string>").count(), 1);
        let removed = remove_launch_services_flock(&updated);
        assert!(removed.contains("com.apple.textedit"));
        assert!(!removed.contains(BUNDLE_ID));
    }
}

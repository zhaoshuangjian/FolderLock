use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{expected_payload_len, Error};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub v: u32,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub dir: bool,
    pub offset: u64,
    pub length: u64,
    pub plain_len: u64,
}

pub fn validate_manifest(manifest: &Manifest, data_start: u64, data_end: u64, chunk_plain: u64) -> Result<(), Error> {
    if manifest.v != 1 {
        return Err(Error::BadManifest);
    }
    if manifest.entries.len() > 1_000_000 {
        return Err(Error::BadLayout);
    }
    if data_end < data_start {
        return Err(Error::BadLayout);
    }
    let mut seen = HashSet::new();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for entry in &manifest.entries {
        validate_rel_path(&entry.path)?;
        if !seen.insert(entry.path.clone()) {
            return Err(Error::BadLayout);
        }
        if entry.dir {
            if entry.offset != 0 || entry.length != 0 || entry.plain_len != 0 {
                return Err(Error::BadLayout);
            }
            continue;
        }
        let expect = expected_payload_len(entry.plain_len, chunk_plain)?;
        if entry.length != expect {
            return Err(Error::BadLayout);
        }
        let end = entry.offset.checked_add(entry.length).ok_or(Error::BadLayout)?;
        if entry.offset < data_start || end > data_end {
            return Err(Error::BadLayout);
        }
        ranges.push((entry.offset, end));
    }
    ranges.sort_unstable();
    let mut prev = data_start;
    for (start, end) in ranges {
        if start < prev {
            return Err(Error::BadLayout);
        }
        prev = end;
    }
    Ok(())
}

pub fn validate_rel_path(path: &str) -> Result<(), Error> {
    if path.is_empty() || path.len() > 32_000 || path.starts_with('/') || path.starts_with('\\') || path.contains('\\') || path.contains(':')
    {
        return Err(Error::BadPath);
    }
    for part in path.split('/') {
        if !valid_component(part) {
            return Err(Error::BadPath);
        }
    }
    Ok(())
}

fn valid_component(part: &str) -> bool {
    if part.is_empty() || part == "." || part == ".." || part.len() > 255 {
        return false;
    }
    if part.ends_with(' ') || part.ends_with('.') {
        return false;
    }
    if part.chars().any(|c| {
        matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') || (c as u32) < 32
    }) {
        return false;
    }
    let stem = part.split('.').next().unwrap_or(part);
    !is_reserved_windows_name(stem)
}

fn is_reserved_windows_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, offset: u64, plain: u64, length: u64) -> Entry {
        Entry {
            path: path.into(),
            dir: false,
            offset,
            length,
            plain_len: plain,
        }
    }

    #[test]
    fn accepts_nested_files_and_empty_dir() {
        let chunk = 64u64;
        let len = expected_payload_len(10, chunk).unwrap();
        let manifest = Manifest {
            v: 1,
            entries: vec![
                Entry {
                    path: "空目录".into(),
                    dir: true,
                    offset: 0,
                    length: 0,
                    plain_len: 0,
                },
                file("笔记/a.txt", 512, 10, len),
            ],
        };
        validate_manifest(&manifest, 512, 512 + len, chunk).unwrap();
    }

    #[test]
    fn rejects_traversal_and_reserved_names() {
        for bad in ["../a", "a/../../b", "/etc/passwd", r"a\b", "con", "aux.txt", "foo/nul", "a//b", ""] {
            assert!(validate_rel_path(bad).is_err(), "{bad}");
        }
        validate_rel_path("笔记/文档.txt").unwrap();
    }

    #[test]
    fn rejects_overlapping_ranges() {
        let chunk = 64u64;
        let len = expected_payload_len(10, chunk).unwrap();
        let manifest = Manifest {
            v: 1,
            entries: vec![file("a", 512, 10, len), file("b", 512, 10, len)],
        };
        assert!(validate_manifest(&manifest, 512, 512 + len * 2, chunk).is_err());
    }
}

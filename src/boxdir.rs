//! Sandbox directory lifecycle: create, list, wipe.
//!
//! A box lives under `%LOCALAPPDATA%\HermesBox\boxes\<id>` by default. The tree is
//! labelled Low integrity (via icacls) so the low-integrity child can write inside
//! it, while everything outside stays off-limits.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn base_dir() -> PathBuf {
    if let Some(h) = std::env::var_os("HERMESBOX_HOME") {
        return PathBuf::from(h);
    }
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    local.join("HermesBox")
}

pub fn boxes_dir() -> PathBuf {
    base_dir().join("boxes")
}

pub fn shared_boxes_dir() -> PathBuf {
    let pd = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    pd.join("HermesBox").join("boxes")
}

pub struct Sandbox {
    pub id: String,
    pub root: PathBuf,
    pub cap_mb: u64,
}

impl Sandbox {
    pub fn create(cap_mb: u64) -> io::Result<Sandbox> {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let id = format!("box-{}-{}", secs, std::process::id());
        Self::create_named(id, cap_mb)
    }

    pub fn create_named(id: String, cap_mb: u64) -> io::Result<Sandbox> {
        let root = boxes_dir().join(&id);
        fs::create_dir_all(&root)?;
        for sub in [
            "profile",
            "profile/Default",
            "cache",
            "temp",
            "home",
            "home/Downloads",
            "home/AppData/Local",
            "home/AppData/Roaming",
        ] {
            fs::create_dir_all(root.join(sub))?;
        }
        let _ = fs::write(root.join("profile").join("First Run"), b"");

        let sb = Sandbox {
            id,
            root,
            cap_mb,
        };
        sb.write_meta()?;
        sb.mark_low_integrity()?;
        Ok(sb)
    }

    fn write_meta(&self) -> io::Result<()> {
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let meta = format!(
            "id={}\nstarted={}\ncap_mb={}\npid={}\n",
            self.id,
            started,
            self.cap_mb,
            std::process::id()
        );
        fs::write(self.root.join("meta.txt"), meta)
    }

    /// Give the whole box tree a Low mandatory integrity label, inherited by
    /// anything the child creates inside it.
    fn mark_low_integrity(&self) -> io::Result<()> {
        set_low_integrity(&self.root)
    }

    pub fn wipe(&self) -> io::Result<()> {
        remove_box_with_retry(&self.root)
    }

    pub fn list() -> io::Result<Vec<BoxInfo>> {
        let dir = boxes_dir();
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let root = entry.path();
            let meta = fs::read_to_string(root.join("meta.txt")).unwrap_or_default();
            let get = |key: &str| -> Option<String> {
                meta.lines()
                    .find_map(|l| l.strip_prefix(&format!("{}=", key)).map(|s| s.to_string()))
            };
            out.push(BoxInfo {
                id: entry.file_name().to_string_lossy().to_string(),
                root,
                started: get("started")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                cap_mb: get("cap_mb").and_then(|s| s.parse().ok()).unwrap_or(0),
                pid: get("pid").and_then(|s| s.parse().ok()).unwrap_or(0),
            });
        }
        out.sort_by(|a, b| b.started.cmp(&a.started));
        Ok(out)
    }
}

pub struct BoxInfo {
    pub id: String,
    pub root: PathBuf,
    pub started: u64,
    pub cap_mb: u64,
    #[allow(dead_code)]
    pub pid: u32,
}

pub fn remove_box_with_retry(root: &Path) -> io::Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for _ in 0..25 {
        if fs::remove_dir_all(root).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    if let Some(parent) = root.parent() {
        if let Some(leaf) = root.file_name() {
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let trash = parent.join(format!("trash-{}-{}", leaf.to_string_lossy(), secs));
            let _ = fs::rename(root, trash);
        }
    }
    Ok(())
}

pub fn wipe_all() -> io::Result<usize> {
    let list = Sandbox::list()?;
    let mut n = 0;
    for b in list {
        remove_box_with_retry(&b.root)?;
        n += 1;
    }
    Ok(n)
}

pub fn set_low_integrity(path: &Path) -> io::Result<()> {
    let status = Command::new("icacls")
        .arg(path)
        .arg("/setintegritylevel")
        .arg("(OI)(CI)L")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("icacls failed to label {}", path.display()),
        ));
    }
    Ok(())
}

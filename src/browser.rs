//! Browser resolution and the low-memory Chromium/Edge switch set.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub fn resolve_chrome() -> Option<PathBuf> {
    let mut paths = vec![
        PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
        PathBuf::from(r"C:\ProgramData\HermesBox\engine\Chrome\chrome.exe"),
    ];
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        paths.push(PathBuf::from(&local).join(r"Google\Chrome\Application\chrome.exe"));
    }
    paths.into_iter().find(|p| p.is_file())
}

pub fn resolve_brave() -> Option<PathBuf> {
    let mut paths = vec![
        PathBuf::from(r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
        PathBuf::from(r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe"),
        PathBuf::from(r"C:\ProgramData\HermesBox\engine\Brave\brave.exe"),
    ];
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        paths.push(PathBuf::from(&local).join(r"BraveSoftware\Brave-Browser\Application\brave.exe"));
    }
    paths.into_iter().find(|p| p.is_file())
}

pub fn resolve_edge() -> Option<PathBuf> {
    candidates(&[
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ])
}

pub fn resolve_auto() -> Option<PathBuf> {
    resolve_chrome()
        .or_else(resolve_brave)
        .or_else(resolve_edge)
}

fn candidates(paths: &[&str]) -> Option<PathBuf> {
    for p in paths {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    None
}

/// Low-memory & privacy switches for sandboxed Chrome / Brave / Edge.
pub fn args(
    root: &Path,
    url: Option<&str>,
    extension: Option<&Path>,
    proxy: Option<&str>,
    low_ram: bool,
    private_mode: bool,
) -> Vec<OsString> {
    let profile = root.join("profile");
    let cache = root.join("cache");
    let renderer_limit = if low_ram { 2 } else { 5 };
    let v8_mb = if low_ram { 256 } else { 512 };

    let mut v: Vec<String> = vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--disk-cache-dir={}", cache.display()),
        "--disk-cache-size=134217728".into(),
        "--media-cache-size=134217728".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-breakpad".into(),
        "--disable-sync".into(),
        "--disable-default-apps".into(),
        "--disable-domain-reliability".into(),
        "--metrics-recording-only".into(),
        "--no-pings".into(),
        "--no-service-autorun".into(),
        "--password-store=basic".into(),
        "--process-per-site".into(),
        format!("--renderer-process-limit={renderer_limit}"),
        format!("--js-flags=--max-old-space-size={v8_mb}"),
        "--force-dark-mode".into(),
        "--enable-gpu-rasterization".into(),
        "--enable-zero-copy".into(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
        "--enable-features=UseEcoQoSForBackgroundProcess,HighEfficiencyModeAvailable".into(),
        "--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication,msEdgeSidebarV2,msHubApps,EdgeCollections,msEdgeShopping,msWelcomePage".into(),
        "--start-maximized".into(),
    ];

    if private_mode {
        v.push("--inprivate".into());
    }
    if let Some(p) = proxy {
        v.push(format!("--proxy-server={p}"));
        v.push("--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE localhost, 127.0.0.1".into());
    }
    if let Some(ext) = extension {
        v.push(format!("--load-extension={}", ext.display()));
    } else {
        let ctrl = Path::new(r"C:\ProgramData\HermesBox\extensions\controller");
        let ub = Path::new(r"C:\ProgramData\HermesBox\extensions\ublock");
        let vpn = Path::new(r"C:\ProgramData\HermesBox\extensions\vpn");
        let mut exts = Vec::new();
        for p in [ctrl, ub, vpn] {
            if p.join("manifest.json").is_file() {
                exts.push(p.display().to_string());
            }
        }
        if !exts.is_empty() {
            v.push(format!("--load-extension={}", exts.join(",")));
        }
    }

    v.push(url.unwrap_or("about:blank").to_string());
    v.into_iter().map(OsString::from).collect()
}

//! Hermes Box - a featherweight, disposable Chromium sandbox for Windows Home.
//!
//! Containment is built from documented Win32 primitives only:
//! restricted low-integrity token + job-object memory ceiling + low-labelled
//! ephemeral profile. No VM, no kernel driver, no Electron.

mod boxdir;
mod browser;
mod win;

use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use boxdir::Sandbox;

type R = Result<(), Box<dyn Error>>;

const DEFAULT_CAP_MB: u64 = 3072;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let cmd = argv.get(1).map(String::as_str).unwrap_or("help");

    let result: R = match cmd {
        "run" => cmd_run(&argv[2..]),
        "list" | "ls" => cmd_list(),
        "wipe" | "rm" => cmd_wipe(&argv[2..]),
        "info" => cmd_info(),
        "selftest" => cmd_selftest(),
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        "-V" | "--version" => {
            println!("hermes {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        r#"Hermes Box {ver}
A featherweight, disposable Chromium sandbox for Windows.

USAGE:
  hermes run [options]        Create a box and launch the browser inside it
  hermes list                 List boxes on disk
  hermes wipe [ID | --all]    Delete a box (or every box)
  hermes info                 Show paths and detected browsers
  hermes selftest             Verify token + job containment works

RUN OPTIONS:
  --cap-mb N        Hard memory ceiling for the whole browser tree (default {cap})
  --url URL         Page to open (default about:blank)
  --browser NAME    edge | chrome | full path to an .exe (default edge)
  --extension DIR   Load an unpacked extension directory
  --keep            Keep the profile after the browser exits

ENV:
  HERMES_HOME       Override the data directory (default %LOCALAPPDATA%\Hermes)

The browser runs with a restricted low-integrity token and cannot write outside
its box. The job object enforces the memory ceiling and reaps stray children.
"#,
        ver = env!("CARGO_PKG_VERSION"),
        cap = DEFAULT_CAP_MB
    );
}

fn parse_u64(flag: &str, v: Option<&String>) -> Result<u64, Box<dyn Error>> {
    let s = v.ok_or_else(|| format!("{flag} needs a value"))?;
    Ok(s.parse()?)
}

fn cmd_run(args: &[String]) -> R {
    let mut cap_mb = DEFAULT_CAP_MB;
    let mut cap_set = false;
    let mut url: Option<String> = None;
    let mut browser_name = String::from("chrome");
    let mut extension: Option<PathBuf> = None;
    let mut proxy: Option<String> = None;
    let mut low_ram = false;
    let mut private_mode = false;
    let mut keep = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cap-mb" | "-CapMb" => {
                i += 1;
                cap_mb = parse_u64("--cap-mb", args.get(i))?;
                cap_set = true;
            }
            "--url" | "-Url" => {
                i += 1;
                url = Some(
                    args.get(i)
                        .ok_or("--url needs a value")?
                        .clone(),
                );
            }
            "--browser" | "-Browser" => {
                i += 1;
                browser_name = args.get(i).ok_or("--browser needs a value")?.clone();
            }
            "--extension" | "-Extension" => {
                i += 1;
                extension = Some(PathBuf::from(args.get(i).ok_or("--extension needs a value")?));
            }
            "--proxy" | "-Proxy" => {
                i += 1;
                proxy = Some(args.get(i).ok_or("--proxy needs a value")?.clone());
            }
            "--low-ram" | "-LowRam" => low_ram = true,
            "--private" | "-Private" => private_mode = true,
            "--keep" | "--no-wipe" | "-Keep" => keep = true,
            other => return Err(format!("unknown option: {other}").into()),
        }
        i += 1;
    }
    if low_ram && !cap_set {
        cap_mb = 900;
    }

    let exe = match browser_name.as_str() {
        "auto" | "chrome" => browser::resolve_auto()
            .ok_or("No supported browser found (install Google Chrome, Brave, or Microsoft Edge)")?,
        "brave" => browser::resolve_brave()
            .or_else(browser::resolve_auto)
            .ok_or("Brave Browser was not found")?,
        "edge" | "msedge" => browser::resolve_edge()
            .or_else(browser::resolve_auto)
            .ok_or("Microsoft Edge was not found in the usual locations")?,
        path => {
            let p = PathBuf::from(path);
            if p.is_file() {
                p
            } else {
                return Err(format!("browser not found: {path}").into());
            }
        }
    };

    let sb = Sandbox::create(cap_mb)?;
    println!("Hermes Box");
    println!("  id      : {}", sb.id);
    println!("  root    : {}", sb.root.display());
    println!("  cap     : {} MB", sb.cap_mb);
    println!("  engine  : {}", exe.display());

    let env = env_overrides(&sb.root);
    let bargs = browser::args(
        &sb.root,
        url.as_deref(),
        extension.as_deref(),
        proxy.as_deref(),
        low_ram,
        private_mode,
    );
    let cap_bytes = cap_mb.saturating_mul(1024 * 1024);

    let child = win::spawn_low(&exe, &bargs, &sb.root, &env, cap_bytes)
        .map_err(|e| win::explain_spawn_error(&e))?;

    println!("  pid     : {}", child.pid);
    println!("  status  : running (job-capped, disposable)");

    let code = child.wait()?;
    drop(child); // closing the job reaps any stray children

    println!("  exit    : {code}");
    if keep {
        println!("  kept    : {}", sb.root.display());
    } else {
        sb.wipe()?;
        println!("  wiped   : yes");
    }
    Ok(())
}

fn cmd_list() -> R {
    let boxes = Sandbox::list()?;
    if boxes.is_empty() {
        println!("no boxes");
        return Ok(());
    }
    println!("{:<26} {:>10} {:>8}  {}", "ID", "STARTED", "CAP MB", "PATH");
    for b in boxes {
        println!(
            "{:<26} {:>10} {:>8}  {}",
            b.id,
            b.started,
            b.cap_mb,
            b.root.display()
        );
    }
    Ok(())
}

fn cmd_wipe(args: &[String]) -> R {
    if args.iter().any(|a| a == "--all" || a == "all") {
        let n = boxdir::wipe_all()?;
        println!("wiped {n} box(es)");
        return Ok(());
    }
    match args.first() {
        Some(id) => {
            let root = boxdir::boxes_dir().join(id);
            if root.exists() {
                fs::remove_dir_all(&root)?;
                println!("wiped {id}");
            } else {
                return Err(format!("no such box: {id}").into());
            }
            Ok(())
        }
        None => Err("usage: hermes wipe <ID> | --all".into()),
    }
}

fn cmd_info() -> R {
    println!("data dir : {}", boxdir::base_dir().display());
    println!("boxes    : {}", boxdir::boxes_dir().display());
    println!("shared   : {}", boxdir::shared_boxes_dir().display());
    println!("default  : {} MB cap", DEFAULT_CAP_MB);
    match browser::resolve_edge() {
        Some(p) => println!("edge     : {}", p.display()),
        None => println!("edge     : not found"),
    }
    match browser::resolve_chrome() {
        Some(p) => println!("chrome   : {}", p.display()),
        None => println!("chrome   : not found"),
    }
    Ok(())
}

fn cmd_selftest() -> R {
    println!("Hermes self-test");

    let sb = Sandbox::create(DEFAULT_CAP_MB)?;
    println!("[1/3] box created: {}", sb.root.display());

    let real_profile = std::env::var("USERPROFILE")?;
    let outside = PathBuf::from(&real_profile).join("hermes_selftest_should_not_exist.txt");
    let _ = fs::remove_file(&outside);

    let env = env_overrides(&sb.root);
    let cmd = std::env::var("ComSpec").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".into());
    let cmd_path = Path::new(&cmd);
    let cap = 512 * 1024 * 1024;

    let args1: Vec<OsString> = vec!["/c".into(), "echo hello> inside.txt".into()];
    let c1 = win::spawn_low(cmd_path, &args1, &sb.root, &env, cap)
        .map_err(|e| win::explain_spawn_error(&e))?;
    let code1 = c1.wait()?;
    drop(c1);
    let inside = sb.root.join("inside.txt");
    let ok1 = inside.exists()
        && fs::read_to_string(&inside)
            .map(|s| s.contains("hello"))
            .unwrap_or(false);
    println!("[2/3] write inside box .... {} (exit {code1})", pass(ok1));

    let args2: Vec<OsString> = vec![
        "/c".into(),
        format!("echo nope> {}", outside.display()).into(),
    ];
    let c2 = win::spawn_low(cmd_path, &args2, &sb.root, &env, cap)
        .map_err(|e| win::explain_spawn_error(&e))?;
    let code2 = c2.wait()?;
    drop(c2);
    let ok2 = !outside.exists();
    println!("[3/3] write outside blocked  {} (exit {code2})", pass(ok2));

    let _ = fs::remove_file(&outside);
    sb.wipe()?;

    if ok1 && ok2 {
        println!("RESULT: PASS");
        Ok(())
    } else {
        Err("self-test failed".into())
    }
}

fn pass(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

/// Environment overrides that keep the child from touching the real profile.
fn env_overrides(root: &Path) -> Vec<(OsString, OsString)> {
    let home = root.join("home");
    let local = home.join("AppData").join("Local");
    let roaming = home.join("AppData").join("Roaming");
    let temp = root.join("temp");

    let mut v: Vec<(OsString, OsString)> = vec![
        ("USERPROFILE".into(), home.clone().into_os_string()),
        ("LOCALAPPDATA".into(), local.clone().into_os_string()),
        ("APPDATA".into(), roaming.into_os_string()),
        ("TEMP".into(), temp.clone().into_os_string()),
        ("TMP".into(), temp.into_os_string()),
        ("HERMES_BOX".into(), root.as_os_str().to_os_string()),
    ];

    let home_s = home.to_string_lossy().to_string();
    if home_s.len() >= 2 && home_s.as_bytes()[1] == b':' {
        v.push(("HOMEDRIVE".into(), OsString::from(&home_s[..2])));
        v.push(("HOMEPATH".into(), OsString::from(&home_s[2..])));
    }
    v
}

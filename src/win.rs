//! Thin, unsafe-ish wrappers around the Windows containment primitives.
//!
//! Everything here is built from documented Win32 APIs:
//!   * a restricted, low-integrity token  (CreateRestrictedToken + SetTokenInformation)
//!   * a job object with a hard memory ceiling (CreateJobObject + SetInformationJobObject)
//!   * a suspended launch so the child cannot fork away before the job is applied
//!
//! No kernel driver, no VM, no admin rights required (privileges are only *used* if
//! the caller happens to hold them).

use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, GetLengthSid, SetTokenInformation,
    DISABLE_MAX_PRIVILEGE, PSID, SECURITY_MAX_SID_SIZE, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel, WinBuiltinAdministratorsSid, WinLowLabelSid,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessWithTokenW, GetCurrentProcess, GetExitCodeProcess,
    OpenProcessToken, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

const MAX_SID_BYTES: usize = SECURITY_MAX_SID_SIZE as usize;
const WAIT_INFINITE: u32 = 0xFFFF_FFFF;
/// SE_GROUP_INTEGRITY, from Win32::System::SystemServices.
const SE_GROUP_INTEGRITY_ATTR: u32 = 0x0000_0020;

fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct Owned(HANDLE);

impl Owned {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Build a restricted token derived from the current process, then drop it to low
/// integrity and remove the Administrators group (deny-only) plus every privilege.
fn make_low_token() -> io::Result<Owned> {
    unsafe {
        let mut base: HANDLE = ptr::null_mut();
        check(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            &mut base,
        ))?;
        let base = Owned(base);

        // Deny-only BUILTIN\Administrators.
        let mut admin_buf = [0u32; MAX_SID_BYTES / 4];
        let mut admin_len = SECURITY_MAX_SID_SIZE;
        let mut sids = [SID_AND_ATTRIBUTES {
            Sid: ptr::null_mut(),
            Attributes: 0,
        }];
        let mut sids_len: u32 = 0;
        if CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            ptr::null_mut(),
            admin_buf.as_mut_ptr() as PSID,
            &mut admin_len,
        ) != 0
        {
            sids[0].Sid = admin_buf.as_mut_ptr() as PSID;
            sids_len = 1;
        }

        let mut restricted: HANDLE = ptr::null_mut();
        check(CreateRestrictedToken(
            base.raw(),
            DISABLE_MAX_PRIVILEGE,
            sids_len,
            if sids_len == 0 {
                ptr::null()
            } else {
                sids.as_ptr()
            },
            0,
            ptr::null(),
            0,
            ptr::null(),
            &mut restricted,
        ))?;
        let restricted = Owned(restricted);

        // Optional low mandatory integrity label. Note: Chromium cannot start its
        // renderer sandbox from a low-integrity browser process, so this is opt-in
        // (HERMES_LOW=1) and intended for detonating non-browser payloads.
        if std::env::var_os("HERMES_LOW").is_some() {
            let mut low_buf = [0u32; MAX_SID_BYTES / 4];
            let mut low_len = SECURITY_MAX_SID_SIZE;
            check(CreateWellKnownSid(
                WinLowLabelSid,
                ptr::null_mut(),
                low_buf.as_mut_ptr() as PSID,
                &mut low_len,
            ))?;
            let low_sid = low_buf.as_mut_ptr() as PSID;

            let tml_size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>();
            let sid_len = GetLengthSid(low_sid) as usize;
            let total = tml_size + sid_len;
            let mut info = vec![0u8; total];
            let sid_dst = info.as_mut_ptr().add(tml_size) as PSID;
            ptr::copy_nonoverlapping(low_sid as *const u8, sid_dst as *mut u8, sid_len);
            let tml = info.as_mut_ptr() as *mut TOKEN_MANDATORY_LABEL;
            (*tml).Label = SID_AND_ATTRIBUTES {
                Sid: sid_dst,
                Attributes: SE_GROUP_INTEGRITY_ATTR,
            };
            check(SetTokenInformation(
                restricted.raw(),
                TokenIntegrityLevel,
                info.as_ptr() as *const c_void,
                total as u32,
            ))?;
        }

        Ok(restricted)
    }
}

fn create_job(cap_bytes: u64) -> io::Result<Owned> {
    unsafe {
        let job = CreateJobObjectW(ptr::null(), ptr::null());
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Owned(job);

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        let min_proc: u64 = 600 * 1024 * 1024;
        if cap_bytes <= min_proc {
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_JOB_MEMORY
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | 0x0000_0400;
            info.ProcessMemoryLimit = cap_bytes as usize;
            info.JobMemoryLimit = cap_bytes as usize;
        } else {
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            info.JobMemoryLimit = cap_bytes as usize;
        }

        check(SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ))?;

        Ok(job)
    }
}

fn quote_arg(s: &str) -> String {
    if !s.is_empty()
        && !s
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '"' | '\n' | '\u{0b}'))
    {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in s.chars() {
        if c == '\\' {
            backslashes += 1;
        } else if c == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(c);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

fn build_cmdline(exe: &Path, args: &[OsString]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(quote_arg(&exe.to_string_lossy()));
    for a in args {
        parts.push(quote_arg(&a.to_string_lossy()));
    }
    parts.join(" ")
}

fn to_wide(s: &OsStr) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_wide().collect();
    v.push(0);
    v
}

fn build_env_block(overrides: &[(OsString, OsString)]) -> Vec<u16> {
    const SAFE_KEYS: &[&str] = &[
        "SystemRoot",
        "windir",
        "ComSpec",
        "SystemDrive",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
        "ProgramData",
        "ALLUSERSPROFILE",
        "PUBLIC",
        "PATHEXT",
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "NUMBER_OF_PROCESSORS",
        "COMPUTERNAME",
    ];

    let mut entries: Vec<(OsString, OsString)> = SAFE_KEYS
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (OsString::from(*k), v)))
        .filter(|(k, _)| {
            let ks = k.to_string_lossy();
            !overrides
                .iter()
                .any(|(ok, _)| ok.to_string_lossy().eq_ignore_ascii_case(&ks))
        })
        .collect();

    let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
    let clean_path = format!(
        r"{sr}\System32;{sr};{sr}\System32\Wbem;{sr}\System32\WindowsPowerShell\v1.0",
        sr = sys_root
    );
    entries.push((OsString::from("PATH"), OsString::from(clean_path)));
    entries.push((OsString::from("USERNAME"), OsString::from("HermesBox")));
    entries.extend(overrides.iter().cloned());
    entries.sort_by(|a, b| {
        a.0.to_string_lossy()
            .to_lowercase()
            .cmp(&b.0.to_string_lossy().to_lowercase())
    });

    let mut block: Vec<u16> = Vec::new();
    for (k, v) in entries {
        let entry = format!("{}={}", k.to_string_lossy(), v.to_string_lossy());
        block.extend(entry.encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// A running sandboxed process plus the job that owns it.
#[allow(dead_code)]
pub struct Child {
    process: HANDLE,
    thread: HANDLE,
    job: Owned,
    pub pid: u32,
}

impl Child {
    pub fn wait(&self) -> io::Result<u32> {
        unsafe {
            let rc = WaitForSingleObject(self.process, WAIT_INFINITE);
            if rc == WAIT_INFINITE {
                return Err(io::Error::last_os_error());
            }
            let mut code: u32 = 0;
            check(GetExitCodeProcess(self.process, &mut code))?;
            Ok(code)
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            if !self.thread.is_null() {
                let _ = CloseHandle(self.thread);
            }
            if !self.process.is_null() {
                let _ = CloseHandle(self.process);
            }
            // Dropping the job with KILL_ON_JOB_CLOSE reaps any stray children.
        }
    }
}

/// Launch `exe` inside a low-integrity restricted token and a memory-capped job.
pub fn spawn_low(
    exe: &Path,
    args: &[OsString],
    cwd: &Path,
    env_overrides: &[(OsString, OsString)],
    cap_bytes: u64,
) -> io::Result<Child> {
    let token = make_low_token()?;
    let job = create_job(cap_bytes)?;

    let cmdline = build_cmdline(exe, args);
    let mut cmd: Vec<u16> = cmdline.encode_utf16().collect();
    cmd.push(0);

    let cwd_w = to_wide(cwd.as_os_str());
    let env_block = build_env_block(env_overrides);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let flags = CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;
    let env_ptr = env_block.as_ptr() as *const c_void;

    let mut created = false;
    let mut last_err: u32 = 0;

    unsafe {
        let ok = CreateProcessAsUserW(
            token.raw(),
            ptr::null(),
            cmd.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            flags,
            env_ptr,
            cwd_w.as_ptr(),
            &si,
            &mut pi,
        );
        if ok != 0 {
            created = true;
        } else {
            last_err = GetLastError();
        }
    }

    if !created {
        unsafe {
            let ok = CreateProcessWithTokenW(
                token.raw(),
                0,
                ptr::null(),
                cmd.as_mut_ptr(),
                flags,
                env_ptr,
                cwd_w.as_ptr(),
                &si,
                &mut pi,
            );
            if ok != 0 {
                created = true;
            } else {
                last_err = GetLastError();
            }
        }
    }

    if !created {
        return Err(io::Error::from_raw_os_error(last_err as i32));
    }

    unsafe {
        let _ = AssignProcessToJobObject(job.raw(), pi.hProcess);
        let _ = ResumeThread(pi.hThread);
    }

    Ok(Child {
        process: pi.hProcess,
        thread: pi.hThread,
        job,
        pid: pi.dwProcessId,
    })
}

pub fn explain_spawn_error(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(1314) => "Windows denied the token hand-off (ERROR_PRIVILEGE_NOT_HELD). \
                       Try running from an elevated terminal."
            .to_string(),
        Some(5) => "Access denied while creating the sandbox process.".to_string(),
        _ => err.to_string(),
    }
}

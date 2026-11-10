#requires -Version 5.1
<#
.SYNOPSIS
  Hermes Box - a featherweight, disposable Chromium sandbox for Windows.

.DESCRIPTION
  Two containment modes:

  account mode (recommended)
    Runs the browser as a dedicated local account via CreateProcessWithLogonW.
    Real SID-level isolation: it cannot read or write your profile at all.
    Create the account once with:  setup-account.ps1  (elevated)

  token mode (fallback, no admin)
    Runs the browser with a restricted token (no Administrators, no privileges)
    inside a memory-capped job object with an ephemeral profile. This blocks
    privilege escalation and gives a disposable profile, but the process still
    runs as you, so it is not a filesystem boundary.

  Both modes put the browser in a job object with a hard memory ceiling and
  wipe the profile on exit. No VM, no kernel driver, no Electron.

.EXAMPLE
  hermesbox run -Url https://example.com -CapMb 1536

.EXAMPLE
  hermesbox run -Url https://www.youtube.com -LowRam -Private

.EXAMPLE
  hermesbox selftest
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command = 'gui',
    [Parameter(Position = 1)][string]$Id,
    [int]$CapMb = 3072,
    [string]$Url,
    [string[]]$Urls = @(),
    [string]$Browser = 'auto',
    [string]$Extension,
    [string]$Proxy,
    [string]$Downloads,
    [int]$TimeoutSec = 0,
    [string[]]$ExtraArgs = @(),
    [switch]$LowRam,
    [switch]$Private,
    [switch]$NoExtensions,
    [switch]$NoUblock,
    [switch]$NoVpn,
    [switch]$Keep,
    [switch]$All,
    [switch]$HideConsole,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$RemainingArgs = @()
)

$ErrorActionPreference = 'Stop'
$script:HermesHome = if ($env:HERMESBOX_HOME) { $env:HERMESBOX_HOME } else { Join-Path $env:LOCALAPPDATA 'HermesBox' }
$script:BoxesDir = Join-Path $script:HermesHome 'boxes'
$script:AccountFile = Join-Path $script:HermesHome 'account.dat'
# Account-mode boxes must live somewhere the separate account can traverse.
# %ProgramData% inherits BUILTIN\Users:(RX), so a subfolder there is reachable.
$script:SharedBase = Join-Path $env:ProgramData 'HermesBox'
$script:SharedBoxes = Join-Path $script:SharedBase 'boxes'
$script:SharedExtensions = Join-Path $script:SharedBase 'extensions'

if ($LowRam -and -not $PSBoundParameters.ContainsKey('CapMb')) {
    $CapMb = 900
}

# ---------------------------------------------------------------------------
# Native containment layer
# ---------------------------------------------------------------------------
$script:nativeSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class HermesNative
{
    const uint TOKEN_QUERY = 0x0008;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    const uint TOKEN_ADJUST_DEFAULT = 0x0080;
    const uint TOKEN_ADJUST_SESSIONID = 0x0100;

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOW
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_UI_RESTRICTIONS
    {
        public uint UIRestrictionsClass;
    }

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateRestrictedToken(IntPtr existing, uint flags,
        uint disableCount, IntPtr disable, uint privCount, IntPtr priv,
        uint restrictCount, IntPtr restrict, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateWellKnownSid(int type, IntPtr domain, IntPtr sid, ref uint cb);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr token, int cls, IntPtr info, uint len);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUserW(IntPtr token, string app, StringBuilder cmd,
        IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string app,
        StringBuilder cmd, uint flags, IntPtr env, string cwd,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithLogonW(string user, string domain, string password,
        uint logonFlags, string app, StringBuilder cmd, uint flags, IntPtr env, string cwd,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateJobObjectW(IntPtr sa, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int cls, IntPtr info, uint len);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr p, out uint code);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    public static void HideConsole()
    {
        IntPtr h = GetConsoleWindow();
        if (h != IntPtr.Zero) ShowWindow(h, 0);
    }

    public sealed class Child : IDisposable
    {
        internal IntPtr process, thread, job;
        public int Pid;

        public int Wait()
        {
            uint r = WaitForSingleObject(process, 0xFFFFFFFF);
            if (r == 0xFFFFFFFF) throw new Exception("WaitForSingleObject: " + Marshal.GetLastWin32Error());
            uint code;
            if (!GetExitCodeProcess(process, out code))
                throw new Exception("GetExitCodeProcess: " + Marshal.GetLastWin32Error());
            return (int)code;
        }

        public bool WaitTimeout(uint ms)
        {
            uint r = WaitForSingleObject(process, ms);
            if (r == 0xFFFFFFFF) throw new Exception("WaitForSingleObject: " + Marshal.GetLastWin32Error());
            return r == 0;
        }

        public void UpdateCap(long capBytes)
        {
            if (job == IntPtr.Zero) return;
            var ji = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            ji.BasicLimitInformation.LimitFlags = 0x200 | 0x2000;
            ji.JobMemoryLimit = (UIntPtr)(ulong)capBytes;
            int jsize = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr jbuf = Marshal.AllocHGlobal(jsize);
            try
            {
                Marshal.StructureToPtr(ji, jbuf, false);
                SetInformationJobObject(job, 9, jbuf, (uint)jsize);
            }
            finally { Marshal.FreeHGlobal(jbuf); }
        }

        public void Dispose()
        {
            if (thread != IntPtr.Zero) { CloseHandle(thread); thread = IntPtr.Zero; }
            if (process != IntPtr.Zero) { CloseHandle(process); process = IntPtr.Zero; }
            if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; }
        }
    }

    static string Quote(string s)
    {
        if (s.Length > 0 && s.IndexOfAny(new char[] { ' ', '\t', '"', '\n', '\v' }) < 0) return s;
        var sb = new StringBuilder();
        sb.Append('"');
        int bs = 0;
        foreach (char c in s)
        {
            if (c == '\\') { bs++; }
            else if (c == '"') { sb.Append('\\', bs * 2 + 1); sb.Append('"'); bs = 0; }
            else { sb.Append('\\', bs); bs = 0; sb.Append(c); }
        }
        sb.Append('\\', bs * 2);
        sb.Append('"');
        return sb.ToString();
    }

    static StringBuilder BuildCmd(string exe, string[] args)
    {
        var cmd = new StringBuilder();
        cmd.Append(Quote(exe));
        foreach (var a in args) { cmd.Append(' '); cmd.Append(Quote(a)); }
        if (Environment.GetEnvironmentVariable("HERMES_DEBUG") == "1")
            Console.Error.WriteLine("CMDLINE: " + cmd.ToString());
        return cmd;
    }

    static readonly string[] SafeEnvKeys = new string[]
    {
        "SystemRoot", "windir", "ComSpec", "SystemDrive",
        "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
        "CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432",
        "ProgramData", "ALLUSERSPROFILE", "PUBLIC", "PATHEXT", "OS",
        "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION", "NUMBER_OF_PROCESSORS", "COMPUTERNAME"
    };

    static IntPtr BuildEnv(string[] pairs)
    {
        // Clean-room environment allowlist: never leak host API keys, tokens, or personal PATH into the sandbox.
        var dict = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string key in SafeEnvKeys)
        {
            string val = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrEmpty(val)) dict[key] = val;
        }
        string sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
        if (string.IsNullOrEmpty(sysRoot)) sysRoot = @"C:\Windows";
        dict["PATH"] = sysRoot + @"\System32;" + sysRoot + ";" + sysRoot + @"\System32\Wbem;" + sysRoot + @"\System32\WindowsPowerShell\v1.0";
        dict["USERNAME"] = "HermesBox";

        foreach (var p in pairs)
        {
            int i = p.IndexOf('=');
            if (i > 0) dict[p.Substring(0, i)] = p.Substring(i + 1);
        }
        var sb = new StringBuilder();
        foreach (var kv in dict) { sb.Append(kv.Key); sb.Append('='); sb.Append(kv.Value); sb.Append('\0'); }
        sb.Append('\0');
        return Marshal.StringToHGlobalUni(sb.ToString());
    }

    static Child Wrap(PROCESS_INFORMATION pi, long capBytes)
    {
        IntPtr job = IntPtr.Zero;
        try
        {
            if (Environment.GetEnvironmentVariable("HERMESBOX_SKIP_JOB") != "1")
            {
                job = CreateJobObjectW(IntPtr.Zero, null);
                if (job == IntPtr.Zero) throw new Exception("CreateJobObject: " + Marshal.GetLastWin32Error());

                var ji = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                long minProc = 600L * 1024L * 1024L;
                if (capBytes <= minProc)
                {
                    ji.BasicLimitInformation.LimitFlags = 0x100 | 0x200 | 0x400 | 0x2000;
                    ji.ProcessMemoryLimit = (UIntPtr)(ulong)capBytes;
                    ji.JobMemoryLimit = (UIntPtr)(ulong)capBytes;
                }
                else
                {
                    // Use Job-level memory limit + Kill-on-close without per-process limit (0x100)
                    // so V8 / WebAssembly virtual cages inside uBlock Origin and tabs never hit 0x5AF.
                    ji.BasicLimitInformation.LimitFlags = 0x200 | 0x2000;
                    ji.JobMemoryLimit = (UIntPtr)(ulong)capBytes;
                }
                int jsize = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                IntPtr jbuf = Marshal.AllocHGlobal(jsize);
                try
                {
                    Marshal.StructureToPtr(ji, jbuf, false);
                    if (!SetInformationJobObject(job, 9, jbuf, (uint)jsize))
                        throw new Exception("SetInformationJobObject: " + Marshal.GetLastWin32Error());
                }
                finally { Marshal.FreeHGlobal(jbuf); }

                // Enforce Win32 UIPI / Desktop isolation (JobObjectBasicUIRestrictions = 4):
                // Blocks HWND shatter/enumeration (0x01), SystemParameters (0x08), DisplaySettings (0x10),
                // GlobalAtoms (0x20), and ExitWindows (0x80) while preserving normal Ctrl+C / Ctrl+V UX
                // unless HERMESBOX_ISOLATE_CLIPBOARD=1 is set (which adds Read/WriteClipboard 0x02|0x04).
                var ui = new JOBOBJECT_BASIC_UI_RESTRICTIONS();
                ui.UIRestrictionsClass = 0x01u | 0x08u | 0x10u | 0x20u | 0x80u;
                if (Environment.GetEnvironmentVariable("HERMESBOX_ISOLATE_CLIPBOARD") == "1")
                    ui.UIRestrictionsClass |= (0x02u | 0x04u);
                int uisize = Marshal.SizeOf(typeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
                IntPtr uibuf = Marshal.AllocHGlobal(uisize);
                try
                {
                    Marshal.StructureToPtr(ui, uibuf, false);
                    SetInformationJobObject(job, 4, uibuf, (uint)uisize);
                }
                finally { Marshal.FreeHGlobal(uibuf); }

                if (!AssignProcessToJobObject(job, pi.hProcess))
                    throw new Exception("AssignProcessToJobObject: " + Marshal.GetLastWin32Error());
            }
            ResumeThread(pi.hThread);

            var child = new Child();
            child.process = pi.hProcess;
            child.thread = pi.hThread;
            child.job = job;
            child.Pid = pi.dwProcessId;
            job = IntPtr.Zero; // ownership moved to Child
            return child;
        }
        catch
        {
            if (job != IntPtr.Zero) CloseHandle(job);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            throw;
        }
    }

    public static Child Start(string exe, string[] args, string cwd, string[] envPairs, long capBytes)
    {
        IntPtr baseTok = IntPtr.Zero, restricted = IntPtr.Zero;
        IntPtr admin = IntPtr.Zero, saBuf = IntPtr.Zero, meSid = IntPtr.Zero;
        IntPtr low = IntPtr.Zero, info = IntPtr.Zero, env = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        try
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                    TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, out baseTok))
                throw new Exception("OpenProcessToken: " + Marshal.GetLastWin32Error());

            admin = Marshal.AllocHGlobal(68);
            uint adminLen = 68;
            bool haveAdmin = CreateWellKnownSid(26, IntPtr.Zero, admin, ref adminLen);
            var sids = new List<SID_AND_ATTRIBUTES>();
            if (haveAdmin)
            {
                var sa = new SID_AND_ATTRIBUTES();
                sa.Sid = admin;
                sa.Attributes = 0;
                sids.Add(sa);
            }

            if (Environment.GetEnvironmentVariable("HERMES_DENY_USER") == "1")
            {
                var me = System.Security.Principal.WindowsIdentity.GetCurrent().User;
                byte[] meBytes = new byte[me.BinaryLength];
                me.GetBinaryForm(meBytes, 0);
                meSid = Marshal.AllocHGlobal(meBytes.Length);
                Marshal.Copy(meBytes, 0, meSid, meBytes.Length);
                var mu = new SID_AND_ATTRIBUTES();
                mu.Sid = meSid;
                mu.Attributes = 0;
                sids.Add(mu);
            }

            int saSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            if (sids.Count > 0)
            {
                saBuf = Marshal.AllocHGlobal(saSize * sids.Count);
                for (int i = 0; i < sids.Count; i++)
                    Marshal.StructureToPtr(sids[i], (IntPtr)(saBuf.ToInt64() + i * saSize), false);
            }

            if (!CreateRestrictedToken(baseTok, 1, (uint)sids.Count,
                    sids.Count == 0 ? IntPtr.Zero : saBuf,
                    0, IntPtr.Zero, 0, IntPtr.Zero, out restricted))
                throw new Exception("CreateRestrictedToken: " + Marshal.GetLastWin32Error());

            if (Environment.GetEnvironmentVariable("HERMES_LOW") == "1")
            {
                low = Marshal.AllocHGlobal(68);
                uint lowLen = 68;
                if (!CreateWellKnownSid(66, IntPtr.Zero, low, ref lowLen))
                    throw new Exception("CreateWellKnownSid: " + Marshal.GetLastWin32Error());
                uint sidLen = GetLengthSid(low);
                int tmlSize = Marshal.SizeOf(typeof(TOKEN_MANDATORY_LABEL));
                int total = tmlSize + (int)sidLen;
                info = Marshal.AllocHGlobal(total);
                for (int i = 0; i < total; i++) Marshal.WriteByte(info, i, 0);
                byte[] sidBytes = new byte[sidLen];
                Marshal.Copy(low, sidBytes, 0, (int)sidLen);
                Marshal.Copy(sidBytes, 0, (IntPtr)(info.ToInt64() + tmlSize), (int)sidLen);
                var tml = new TOKEN_MANDATORY_LABEL();
                tml.Label.Sid = (IntPtr)(info.ToInt64() + tmlSize);
                tml.Label.Attributes = 0x20;
                Marshal.StructureToPtr(tml, info, false);
                if (!SetTokenInformation(restricted, 25, info, (uint)total))
                    throw new Exception("SetTokenInformation: " + Marshal.GetLastWin32Error());
            }

            env = BuildEnv(envPairs);
            var cmd = BuildCmd(exe, args);

            var si = new STARTUPINFOW();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
            uint flags = 0x4 | 0x400;

            bool ok = CreateProcessAsUserW(restricted, null, cmd, IntPtr.Zero, IntPtr.Zero,
                false, flags, env, cwd, ref si, out pi);
            if (!ok)
            {
                int first = Marshal.GetLastWin32Error();
                ok = CreateProcessWithTokenW(restricted, 0, null, cmd, flags, env, cwd,
                    ref si, out pi);
                if (!ok)
                    throw new Exception("CreateProcess failed: " + Marshal.GetLastWin32Error() +
                        " (CreateProcessAsUser: " + first + ")");
            }

            return Wrap(pi, capBytes);
        }
        finally
        {
            if (baseTok != IntPtr.Zero) CloseHandle(baseTok);
            if (restricted != IntPtr.Zero) CloseHandle(restricted);
            if (admin != IntPtr.Zero) Marshal.FreeHGlobal(admin);
            if (saBuf != IntPtr.Zero) Marshal.FreeHGlobal(saBuf);
            if (meSid != IntPtr.Zero) Marshal.FreeHGlobal(meSid);
            if (low != IntPtr.Zero) Marshal.FreeHGlobal(low);
            if (info != IntPtr.Zero) Marshal.FreeHGlobal(info);
            if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
        }
    }

    public static Child StartAsUser(string user, string password, string exe, string[] args,
        string cwd, string[] envPairs, long capBytes)
    {
        IntPtr env = IntPtr.Zero;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        try
        {
            env = BuildEnv(envPairs);
            var cmd = BuildCmd(exe, args);
            if (cmd.Length >= 1020)
                throw new Exception("Command line length (" + cmd.Length +
                    " chars) exceeds CreateProcessWithLogonW 1024-char limit. Reduce extra arguments.");
            var si = new STARTUPINFOW();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
            uint flags = 0x4 | 0x400;

            bool ok = CreateProcessWithLogonW(user, ".", password, 1, null, cmd,
                flags, env, cwd, ref si, out pi);
            if (!ok)
                throw new Exception("CreateProcessWithLogon: " + Marshal.GetLastWin32Error());

            return Wrap(pi, capBytes);
        }
        finally
        {
            if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
        }
    }
}
'@

function Ensure-Native {
    if (-not ('HermesNative' -as [type])) {
        Add-Type -TypeDefinition $script:nativeSource -Language CSharp
    }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Sync-PerUserBrowser([string]$srcExe, [string]$engineTag = 'Chrome') {
    if (-not $srcExe -or -not (Test-Path -LiteralPath $srcExe -PathType Leaf)) { return $null }
    $srcRoot = Split-Path -Parent $srcExe
    $leafExe = Split-Path -Leaf $srcExe

    # System-wide installs under Program Files are already readable by the sandbox account.
    if ($srcExe -notlike "$env:USERPROFILE*") {
        return $srcExe
    }

    $dstRoot = Join-Path $script:SharedBase "engine\$engineTag"
    $dstExe = Join-Path $dstRoot $leafExe
    $needsSync = $true
    if (Test-Path -LiteralPath $dstExe -PathType Leaf) {
        $sItem = Get-Item -LiteralPath $srcExe
        $dItem = Get-Item -LiteralPath $dstExe
        if ($sItem.Length -eq $dItem.Length -and $sItem.LastWriteTimeUtc -eq $dItem.LastWriteTimeUtc) {
            $needsSync = $false
        }
    }
    if ($needsSync) {
        if (Test-Path -LiteralPath $dstRoot) {
            Remove-Item -LiteralPath $dstRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Force -Path $dstRoot | Out-Null
        Get-ChildItem -LiteralPath $srcRoot -Recurse -Force | ForEach-Object {
            if ($_.Name -eq 'debug.log') { return }
            $rel = $_.FullName.Substring($srcRoot.Length).TrimStart('\')
            $target = Join-Path $dstRoot $rel
            if ($_.PSIsContainer) {
                New-Item -ItemType Directory -Force -Path $target | Out-Null
            }
            else {
                $parent = Split-Path -Parent $target
                if (-not (Test-Path -LiteralPath $parent)) {
                    New-Item -ItemType Directory -Force -Path $parent | Out-Null
                }
                New-Item -ItemType HardLink -Path $target -Value $_.FullName -Force | Out-Null
            }
        }
        $callerId = "$env:USERDOMAIN\$env:USERNAME"
        $p = Start-Process -FilePath 'icacls.exe' -ArgumentList @(
            $dstRoot, '/inheritance:r',
            '/grant', '*S-1-5-18:(OI)(CI)(F)',
            '/grant', '*S-1-5-32-544:(OI)(CI)(F)',
            '/grant', "${callerId}:(OI)(CI)(F)",
            '/grant', '*S-1-5-32-545:(OI)(CI)(RX)',
            '/grant', '*S-1-5-32-545:(RX)',
            '/T', '/Q'
        ) -Wait -PassThru -WindowStyle Hidden
    }
    return $dstExe
}

function Resolve-Browser([string]$name, [switch]$Strict) {
    $n = if ($name) { $name.ToLowerInvariant() } else { 'auto' }

    $chromePaths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    $bravePaths = @(
        "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
        "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe"
    )
    $chromiumPaths = @(
        "$env:ProgramFiles\Chromium\Application\chrome.exe",
        "$env:LOCALAPPDATA\Chromium\Application\chrome.exe",
        "$env:LOCALAPPDATA\imput\Helium\Application\chrome.exe"
    )
    $edgePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    )

    $candidates = if ($Strict) {
        switch ($n) {
            'chrome'   { $chromePaths }
            'brave'    { $bravePaths }
            'chromium' { $chromiumPaths }
            'edge'     { $edgePaths }
            default    { $chromePaths + $bravePaths + $chromiumPaths + $edgePaths }
        }
    } else {
        switch ($n) {
            'auto'     { $chromePaths + $bravePaths + $chromiumPaths + $edgePaths }
            'chrome'   { $chromePaths + $bravePaths + $chromiumPaths + $edgePaths }
            'brave'    { $bravePaths + $chromePaths + $edgePaths }
            'chromium' { $chromiumPaths + $chromePaths + $edgePaths }
            'helium'   { @("$env:LOCALAPPDATA\imput\Helium\Application\chrome.exe") + $chromePaths + $edgePaths }
            'edge'     { $edgePaths + $chromePaths }
            'msedge'   { $edgePaths + $chromePaths }
            default    { @($name) + $chromePaths + $edgePaths }
        }
    }
    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) {
            $full = (Resolve-Path -LiteralPath $p).Path
            $tag = if ($full -match 'Brave') { 'Brave' } elseif ($full -match 'Helium') { 'Helium' } elseif ($full -match 'Edge') { 'Edge' } else { 'Chrome' }
            return (Sync-PerUserBrowser $full $tag)
        }
    }
    throw "browser not found: $name (install Google Chrome, Brave, or Microsoft Edge)"
}

function Set-LowIntegrity([string]$path) {
    $p = Start-Process -FilePath 'icacls.exe' -ArgumentList @($path, '/setintegritylevel', '(OI)(CI)L') -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "icacls failed to label $path (exit $($p.ExitCode))" }
}

function Set-BoxAcl([string]$root, [string]$account) {
    # Fast in-process .NET ACL setup on empty $root BEFORE creating subdirectories (~300 ms vs 2,370 ms for 3x icacls.exe).
    # Grants Modify strictly to the dedicated sandbox account (not all local Users) + caller + SYSTEM + Administrators.
    $acl = Get-Acl -LiteralPath $root
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $none    = [System.Security.AccessControl.PropagationFlags]::None

    foreach ($sidStr in @('S-1-5-18', 'S-1-5-32-544')) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, $none, 'Allow')))
    }
    $meSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($meSid, 'FullControl', $inherit, $none, 'Allow')))

    if ($account) {
        try {
            $sbSid = (New-Object System.Security.Principal.NTAccount($account)).Translate([System.Security.Principal.SecurityIdentifier])
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sbSid, 'Modify', $inherit, $none, 'Allow')))
        }
        catch {
            $usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid, 'Modify', $inherit, $none, 'Allow')))
        }
    }
    Set-Acl -LiteralPath $root -AclObject $acl
    if ($env:HERMES_LOW -eq '1') {
        Set-LowIntegrity $root
    }
}

function Save-QuarantineDownloads([string]$boxRoot, [string]$destDir) {
    # Safe quarantine extraction: rejects NTFS junctions/symlinks (preventing ReparsePoint host exfiltration)
    # and stamps Mark-of-the-Web (ZoneId=3) on saved files.
    $boxDl = Join-Path $boxRoot 'home\Downloads'
    if (-not (Test-Path -LiteralPath $boxDl)) { return 0 }
    $dlRootItem = Get-Item -LiteralPath $boxDl -Force -ErrorAction SilentlyContinue
    if (-not $dlRootItem -or (($dlRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { return 0 }

    New-Item -ItemType Directory -Force -Path $destDir | Out-Null
    $savedCount = 0
    $files = @(Get-ChildItem -LiteralPath $boxDl -File -Force -ErrorAction SilentlyContinue |
        Where-Object {
            (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) -and
            ($_.Extension -notin @('.crdownload', '.tmp', '.part'))
        })
    foreach ($f in $files) {
        $safeLeaf = [IO.Path]::GetFileName($f.Name)
        if (-not $safeLeaf) { continue }
        $dstFile = Join-Path $destDir $safeLeaf
        Copy-Item -LiteralPath $f.FullName -Destination $dstFile -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $dstFile -PathType Leaf) {
            try {
                Set-Content -LiteralPath $dstFile -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ASCII -ErrorAction SilentlyContinue
            } catch { }
            $savedCount++
        }
    }
    return $savedCount
}

function Ensure-SharedBase {
    if (-not (Test-Path -LiteralPath $script:SharedBoxes)) {
        New-Item -ItemType Directory -Force -Path $script:SharedBoxes | Out-Null
    }
}

function Get-BoxDirs {
    @($script:BoxesDir, $script:SharedBoxes) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -Unique
}

function Set-ControllerInitState([bool]$enableUblock, [bool]$enableVpn, [string]$modeLabel, [string]$capLabel) {
    $ctrlDir = Join-Path $script:SharedExtensions 'controller'
    if (Test-Path -LiteralPath $ctrlDir) {
        $initFile = Join-Path $ctrlDir 'init_state.json'
        $stateObj = @{
            ublock = $enableUblock
            vpn    = $enableVpn
            mode   = $modeLabel
            cap    = $capLabel
        } | ConvertTo-Json -Compress
        try {
            Set-Content -LiteralPath $initFile -Value $stateObj -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch { }
    }
}

function Get-DefaultExtensionPaths([string]$extraExt, [bool]$skipDefaults = $false) {
    $list = @()
    if (-not $skipDefaults) {
        foreach ($sub in @('controller', 'ublock', 'vpn')) {
            $p = Join-Path $script:SharedExtensions $sub
            if (Test-Path -LiteralPath (Join-Path $p 'manifest.json') -PathType Leaf) {
                $list += $p
            }
        }
    }
    if ($extraExt) {
        foreach ($e in ($extraExt -split ',')) {
            $t = $e.Trim()
            if ($t -and ($list -notcontains $t)) { $list += $t }
        }
    }
    return ($list -join ',')
}

function Initialize-BrowserProfile([string]$root, [string]$downloadsDir, [string[]]$startupUrls) {
    $profDir = Join-Path $root 'profile'
    $defDir = Join-Path $profDir 'Default'
    New-Item -ItemType Directory -Force -Path $defDir | Out-Null

    # Sentinel file telling Chromium/Edge that first-run setup is already complete.
    Set-Content -LiteralPath (Join-Path $profDir 'First Run') -Value '' -Encoding ASCII

    $dlTarget = if ($downloadsDir) { $downloadsDir } else { Join-Path $root 'home\Downloads' }
    New-Item -ItemType Directory -Force -Path $dlTarget | Out-Null

    $prefs = @{
        download = @{
            default_directory = $dlTarget
            prompt_for_download = $false
        }
        Savefile = @{
            default_directory = $dlTarget
        }
        credentials_enable_service = $false
        credentials_enable_autosignin = $false
        profile = @{
            password_manager_enabled = $false
            cookie_controls_mode = 1
            default_content_setting_values = @{
                notifications = 2
                geolocation = 2
                clipboard = 2
                automatic_downloads = 2
                popups = 2
                sensors = 2
                usb_guard = 2
                serial_guard = 2
                hid_guard = 2
                bluetooth_guard = 2
                local_fonts = 2
            }
        }
        safebrowsing = @{
            enabled = $true
        }
        webrtc = @{
            ip_handling_policy = 'disable_non_proxied_udp'
        }
        autofill = @{
            credit_card_enabled = $false
            profile_enabled = $false
        }
        translate = @{
            enabled = $false
        }
        https_only_mode_auto_enabled = $true
        browser = @{
            has_seen_welcome_page = $true
            show_hub_apps_tower = $false
            theme = @{
                color_scheme = 2
                color_scheme2 = 2
                follow_device_theme = $false
            }
        }
        extensions = @{
            pinned_extensions = @(
                'ajjibhjidlpbekdkdkkifhkiiibmkdnj',
                'kggmfbbahicjjengfajhfpggdcdphfkl',
                'flokmmfhjhogkkadaahlidjlbilkabme'
            )
        }
        helium = @{
            completed_onboarding = $true
            services = @{
                schema_version = 1
                user_consented = $true
            }
        }
        edge = @{
            sidebar = @{
                sidebar_enabled = $false
            }
            shopping = @{
                enabled = $false
            }
        }
    }
    if ($startupUrls -and $startupUrls.Count -gt 1) {
        $prefs['session'] = @{
            restore_on_startup = 4
            startup_urls = @($startupUrls)
        }
    }
    $prefsJson = $prefs | ConvertTo-Json -Depth 6 -Compress
    Set-Content -LiteralPath (Join-Path $defDir 'Preferences') -Value $prefsJson -Encoding UTF8

    $localState = @{
        background_mode = @{ enabled = $false }
        hardware_acceleration_mode = @{ enabled = $true }
        performance_tuning = @{
            high_efficiency_mode = @{ state = 2; time_before_discard_in_minutes = 10 }
        }
    } | ConvertTo-Json -Depth 5 -Compress
    Set-Content -LiteralPath (Join-Path $profDir 'Local State') -Value $localState -Encoding UTF8
}

function New-Box([int]$cap, [string]$account, [string]$downloadsDir, [string[]]$startupUrls = @()) {
    $id = 'box-{0}-{1}' -f [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(), $PID
    if ($account) {
        Ensure-SharedBase
        $root = Join-Path $script:SharedBoxes $id
    }
    else {
        $root = Join-Path $script:BoxesDir $id
    }
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Set-BoxAcl $root $account
    foreach ($sub in @('profile', 'cache', 'temp', 'home', 'home/Downloads', 'home/AppData/Local', 'home/AppData/Roaming')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $root $sub) | Out-Null
    }
    Initialize-BrowserProfile $root $downloadsDir $startupUrls
    $meta = @(
        "id=$id"
        "started=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        "cap_mb=$cap"
        "pid=$PID"
    ) -join "`n"
    Set-Content -LiteralPath (Join-Path $root 'meta.txt') -Value $meta -Encoding ASCII
    [pscustomobject]@{ Id = $id; Root = $root; CapMb = $cap }
}

function Get-AccountCredential {
    if ($env:HERMESBOX_FORCE_TOKEN -eq '1') { return $null }
    if (-not (Test-Path -LiteralPath $script:AccountFile)) { return $null }
    try {
        $obj = Get-Content -LiteralPath $script:AccountFile -Raw | ConvertFrom-Json
        $sec = ConvertTo-SecureString $obj.password
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { $pw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        return [pscustomobject]@{ User = $obj.user; Password = $pw }
    }
    catch {
        Write-Warning "could not read $($script:AccountFile): $($_.Exception.Message)"
        return $null
    }
}

function Get-EnvPairs([string]$root) {
    $boxHome = Join-Path $root 'home'
    $local = Join-Path $boxHome 'AppData\Local'
    $roaming = Join-Path $boxHome 'AppData\Roaming'
    $temp = Join-Path $root 'temp'
    $pairs = @(
        "USERPROFILE=$boxHome"
        "LOCALAPPDATA=$local"
        "APPDATA=$roaming"
        "TEMP=$temp"
        "TMP=$temp"
        "HERMES_BOX=$root"
    )
    if ($boxHome.Length -ge 2 -and $boxHome[1] -eq ':') {
        $pairs += "HOMEDRIVE=$($boxHome.Substring(0,2))"
        $pairs += "HOMEPATH=$($boxHome.Substring(2))"
    }
    return $pairs
}

function Get-BrowserArgs([string]$root, [string]$page, [string[]]$pageList, [string]$ext, [string]$proxyUrl, [bool]$isLowRam, [bool]$isPrivate, [string[]]$extra, [string]$exePath = '', [bool]$skipDefaultExts = $false) {
    if ($env:HERMESBOX_EXTRA) { $extra = @(($env:HERMESBOX_EXTRA -split '\s+') + $extra) }
    $profile = Join-Path $root 'profile'
    $cache = Join-Path $root 'cache'
    $rendererLimit = 4
    $v8Mb = 256
    $isEdge = ($exePath -match 'msedge\.exe$')
    $disFeatures = if ($isEdge) {
        'Translate,MediaRouter,OptimizationHints,AutofillServerCommunication,msEdgeSidebarV2,msHubApps'
    } else {
        'Translate,MediaRouter,OptimizationHints,AutofillServerCommunication,ChromeWhatsNewUI,PrivacySandboxSettings4,SidePanelPinning,LensOverlay,Compose'
    }
    $a = @(
        "--user-data-dir=$profile"
        "--disk-cache-dir=$cache"
        '--disk-cache-size=104857600'
        '--media-cache-size=134217728'
        '--site-per-process'
        '--no-first-run'
        '--no-default-browser-check'
        '--disable-breakpad'
        '--disable-sync'
        '--disable-default-apps'
        '--disable-domain-reliability'
        '--metrics-recording-only'
        '--no-pings'
        '--no-service-autorun'
        '--password-store=basic'
        '--force-dark-mode'
        '--enable-gpu-rasterization'
        '--enable-zero-copy'
        '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'
        '--enable-features=UseEcoQoSForBackgroundProcess,HighEfficiencyModeAvailable,HttpsUpgrades'
        "--disable-features=$disFeatures"
    )
    if ($isLowRam) {
        $a += '--process-per-site'
        $a += "--renderer-process-limit=$rendererLimit"
        $a += "--js-flags=--max-old-space-size=$v8Mb"
    }
    if ($isPrivate) {
        if ($isEdge) { $a += '--inprivate' } else { $a += '--incognito' }
    }
    if ($proxyUrl) {
        $a += "--proxy-server=$proxyUrl"
        $a += '--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE localhost, 127.0.0.1'
    }
    $resolvedExts = Get-DefaultExtensionPaths $ext $skipDefaultExts
    if ($resolvedExts) { $a += "--load-extension=$resolvedExts" }
    if ($extra) {
        if ($extra.Count -eq 1 -and $extra[0] -match '\s') { $a += ($extra[0] -split '\s+') }
        else { $a += $extra }
    }
    if (-not (($a -join ' ') -match 'headless')) { $a += '--start-maximized' }
    $allPages = @()
    if ($page) { $allPages += $page }
    if ($pageList -and $pageList.Count -gt 0) { $allPages += $pageList }
    if ($allPages.Count -eq 1 -and $allPages[0].Length -le 220) {
        $a += $allPages[0]
    }
    elseif ($allPages.Count -gt 1) {
        # Multiple tabs are already pre-seeded via Preferences (session.startup_urls) so none get dropped or hit the 1024-char RPC limit.
    }
    else {
        $a += 'chrome://newtab'
    }
    return $a
}

function Start-Boxed([string]$exe, [string[]]$argList, [string]$root, [string[]]$env, [int]$capMb, $cred) {
    Ensure-Native
    $capBytes = [int64]$capMb * 1024L * 1024L
    if ($cred) {
        return [HermesNative]::StartAsUser($cred.User, $cred.Password, $exe, $argList, $root, $env, $capBytes)
    }
    return [HermesNative]::Start($exe, $argList, $root, $env, $capBytes)
}

function Read-BoxMeta([string]$root) {
    $meta = @{}
    $mf = Join-Path $root 'meta.txt'
    if (Test-Path -LiteralPath $mf) {
        foreach ($line in Get-Content -LiteralPath $mf -ErrorAction SilentlyContinue) {
            $i = $line.IndexOf('=')
            if ($i -gt 0) { $meta[$line.Substring(0, $i)] = $line.Substring($i + 1) }
        }
    }
    return $meta
}

function Invoke-Sweep {
    # Remove boxes whose owning launcher is gone (crashed, killed, or a wipe that
    # was deferred because a file was still locked). Active boxes have a live pid.
    foreach ($dir in @(Get-BoxDirs)) {
        foreach ($b in (Get-ChildItem -LiteralPath $dir -Directory -ErrorAction SilentlyContinue)) {
            $meta = Read-BoxMeta $b.FullName
            if ($meta['keep'] -eq '1') { continue }
            $ownerPid = 0
            [void][int]::TryParse([string]$meta['pid'], [ref]$ownerPid)
            $isTrash = $b.Name -like 'trash-*'
            if (-not $isTrash -and $ownerPid -gt 0 -and (Get-Process -Id $ownerPid -ErrorAction SilentlyContinue)) {
                continue
            }
            try { Remove-Item -LiteralPath $b.FullName -Recurse -Force -ErrorAction Stop } catch { }
        }
    }
}

function Remove-Box([string]$root) {
    if (-not (Test-Path -LiteralPath $root)) { return $true }
    # Chromium processes die asynchronously when the job closes, and Defender or the
    # profile service can hold a handle for a few seconds. Wait them out.
    for ($attempt = 0; $attempt -lt 25; $attempt++) {
        try {
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
            return $true
        }
        catch {
            Start-Sleep -Milliseconds 400
        }
    }
    # Still locked: rename it out of the way. The next hermes command sweeps it.
    try {
        $parent = Split-Path -Parent $root
        $trash = Join-Path $parent ('trash-' + (Split-Path -Leaf $root) + '-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        Move-Item -LiteralPath $root -Destination $trash -ErrorAction Stop
    }
    catch { }
    return $false
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
function Invoke-Run {
    $exe = Resolve-Browser $Browser
    $cred = Get-AccountCredential
    $allUrls = @()
    if ($Url) { $allUrls += ($Url -split ',') }
    if ($Urls -and $Urls.Count -gt 0) {
        foreach ($u in $Urls) { $allUrls += ($u -split ',') }
    }
    if ($Id -and $Id -match '^https?://|^about:') { $allUrls += ($Id -split ',') }
    if ($RemainingArgs -and $RemainingArgs.Count -gt 0) {
        foreach ($r in $RemainingArgs) {
            if ($r -match '^https?://|^about:') { $allUrls += ($r -split ',') }
        }
    }
    $allUrls = @($allUrls | Where-Object { $_ } | Select-Object -Unique)

    $dlDir = $null
    if ($Downloads) {
        New-Item -ItemType Directory -Force -Path $Downloads | Out-Null
        $dlDir = (Resolve-Path -LiteralPath $Downloads).Path
    }
    $box = New-Box $CapMb $(if ($cred) { $cred.User } else { $null }) $null $allUrls
    $mode = if ($cred) { "account ($($cred.User))" } else { 'token (limited isolation)' }
    $preset = if ($LowRam) { 'low-ram (4 renderers, 256 MB V8)' } else { 'standard (strict site-isolation, GPU zero-copy, 128 MB media cache)' }
    Set-ControllerInitState (-not [bool]$NoUblock) (-not [bool]$NoVpn) $mode "$($box.CapMb) MB"
    Write-Host 'Hermes Box'
    Write-Host "  id      : $($box.Id)"
    Write-Host "  root    : $($box.Root)"
    Write-Host "  cap     : $($box.CapMb) MB"
    Write-Host "  preset  : $preset"
    Write-Host "  mode    : $mode"
    Write-Host "  engine  : $exe"
    if ($Proxy) { Write-Host "  proxy   : $Proxy (DNS leak protection active)" }
    if ($dlDir) { Write-Host "  saves   : $dlDir (quarantine copy on exit)" }

    $envPairs = Get-EnvPairs $box.Root
    $bargs = Get-BrowserArgs $box.Root $null $allUrls $Extension $Proxy ([bool]$LowRam) ([bool]$Private) $ExtraArgs $exe ([bool]$NoExtensions)
    $child = Start-Boxed $exe $bargs $box.Root $envPairs $box.CapMb $cred
    try {
        Write-Host "  pid     : $($child.Pid)"
        Write-Host '  status  : running (job-capped, disposable)'
        if ($TimeoutSec -gt 0) {
            $finished = $child.WaitTimeout([uint32]($TimeoutSec * 1000))
            if ($finished) { Write-Host "  exit    : $($child.Wait())" }
            else { Write-Host "  exit    : timeout after $TimeoutSec s" }
        }
        else {
            Write-Host '  tip     : close the browser to finish'
            Write-Host "  exit    : $($child.Wait())"
        }
    }
    finally {
        $child.Dispose()
    }

    if ($dlDir) {
        $savedN = Save-QuarantineDownloads $box.Root $dlDir
        if ($savedN -gt 0) {
            Write-Host "  saved   : $savedN file(s) -> $dlDir (Mark-of-the-Web applied)"
        }
    }

    if ($Keep) {
        Add-Content -LiteralPath (Join-Path $box.Root 'meta.txt') -Value 'keep=1' -Encoding ASCII
        Write-Host "  kept    : $($box.Root)"
    }
    elseif (Remove-Box $box.Root) { Write-Host '  wiped   : yes' }
    else { Write-Host '  wiped   : deferred (file still locked; next run cleans it)' }
}

function Invoke-List {
    $dirs = @(Get-BoxDirs)
    if ($dirs.Count -eq 0) { Write-Host 'no boxes'; return }
    $boxes = @($dirs | ForEach-Object { Get-ChildItem -LiteralPath $_ -Directory -ErrorAction SilentlyContinue } | Sort-Object Name -Descending)
    if ($boxes.Count -eq 0) { Write-Host 'no boxes'; return }
    '{0,-26} {1,10} {2,8}  {3}' -f 'ID', 'STARTED', 'CAP MB', 'PATH' | Write-Host
    foreach ($b in $boxes) {
        $meta = @{}
        $mf = Join-Path $b.FullName 'meta.txt'
        if (Test-Path -LiteralPath $mf) {
            foreach ($line in Get-Content -LiteralPath $mf) {
                $i = $line.IndexOf('=')
                if ($i -gt 0) { $meta[$line.Substring(0, $i)] = $line.Substring($i + 1) }
            }
        }
        '{0,-26} {1,10} {2,8}  {3}' -f $b.Name, $meta['started'], $meta['cap_mb'], $b.FullName | Write-Host
    }
}

function Invoke-Wipe {
    if ($All) {
        $boxes = @(Get-BoxDirs | ForEach-Object { Get-ChildItem -LiteralPath $_ -Directory -ErrorAction SilentlyContinue })
        if ($boxes.Count -eq 0) { Write-Host 'wiped 0 box(es)'; return }
        $ok = 0
        foreach ($b in $boxes) {
            $meta = Read-BoxMeta $b.FullName
            if ($meta['keep'] -eq '1') { continue }
            $ownerPid = 0
            [void][int]::TryParse([string]$meta['pid'], [ref]$ownerPid)
            if ($b.Name -notlike 'trash-*' -and $ownerPid -gt 0 -and (Get-Process -Id $ownerPid -ErrorAction SilentlyContinue)) {
                continue
            }
            if (Remove-Box $b.FullName) { $ok++ }
        }
        Write-Host "wiped $ok box(es)"
        return
    }
    if (-not $Id) { throw 'usage: hermes.ps1 wipe <ID> | -All' }
    $root = $null
    foreach ($dir in @(Get-BoxDirs)) {
        $candidate = Join-Path $dir $Id
        if (Test-Path -LiteralPath $candidate) { $root = $candidate; break }
    }
    if (-not $root) { throw "no such box: $Id" }
    if (Remove-Box $root) { Write-Host "wiped $Id" }
    else { Write-Host "deferred $Id (file still locked; next run retries)" }
}

function Invoke-Info {
    Write-Host "data dir : $script:HermesHome"
    Write-Host "boxes    : $script:BoxesDir"
    Write-Host "shared   : $script:SharedBoxes (used by account mode)"
    Write-Host "default  : 3072 MB job commit ceiling (auto-scaled)"
    try { Write-Host ("{0,-9}: {1}" -f 'active', (Resolve-Browser 'auto')) }
    catch { Write-Host ("{0,-9}: not found" -f 'active') }
    foreach ($name in @('chrome', 'brave', 'edge')) {
        try { Write-Host ("{0,-9}: {1}" -f $name, (Resolve-Browser $name -Strict)) }
        catch { Write-Host ("{0,-9}: not found" -f $name) }
    }
    $cred = Get-AccountCredential
    if ($cred) { Write-Host "isolation: account mode ($($cred.User))" }
    else { Write-Host 'isolation: token mode (run setup-account.ps1 elevated for full isolation)' }
    $sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
    Write-Host ("SAC      : {0}" -f $(if ($sac -eq 1) { 'ON (unsigned .exe blocked; this script runs under signed pwsh)' } elseif ($sac -eq 0) { 'OFF' } else { 'unknown' }))
}

function Invoke-SelfTest {
    Write-Host 'Hermes Box self-test'
    $cred = Get-AccountCredential
    $mode = if ($cred) { "account ($($cred.User))" } else { 'token (no filesystem boundary)' }
    Write-Host "mode: $mode"
    $box = New-Box 1536 $(if ($cred) { $cred.User } else { $null }) $null
    Write-Host "[1/5] box created: $($box.Root)"

    $realProfile = $env:USERPROFILE
    $outside = Join-Path $realProfile 'hermes_selftest_should_not_exist.txt'
    Remove-Item -LiteralPath $outside -Force -ErrorAction SilentlyContinue

    $envPairs = Get-EnvPairs $box.Root
    $cmd = if ($env:ComSpec) { $env:ComSpec } else { "$env:SystemRoot\System32\cmd.exe" }
    $okAll = $true

    $c1 = Start-Boxed $cmd @('/c', 'echo hello> inside.txt') $box.Root $envPairs 512 $cred
    try { $code1 = $c1.Wait() } finally { $c1.Dispose() }
    $inside = Join-Path $box.Root 'inside.txt'
    $ok1 = (Test-Path -LiteralPath $inside) -and ((Get-Content -LiteralPath $inside -Raw -ErrorAction SilentlyContinue) -match 'hello')
    Write-Host ("[2/5] write inside box .... {0} (exit {1})" -f $(if ($ok1) { 'PASS' } else { 'FAIL' }), $code1)
    if (-not $ok1) { $okAll = $false }

    $c2 = Start-Boxed $cmd @('/c', "echo nope> $outside") $box.Root $envPairs 512 $cred
    try { $code2 = $c2.Wait() } finally { $c2.Dispose() }
    if ($cred) {
        $ok2 = -not (Test-Path -LiteralPath $outside)
        Write-Host ("[3/5] write outside blocked  {0} (exit {1})" -f $(if ($ok2) { 'PASS' } else { 'FAIL' }), $code2)
        if (-not $ok2) { $okAll = $false }
    }
    else {
        Write-Host ("[3/5] write outside blocked  SKIP (token mode has no filesystem boundary; got exit {0})" -f $code2)
    }

    # A second account must not be able to read your private files at all.
    $secret = $script:AccountFile
    if ($cred -and (Test-Path -LiteralPath $secret)) {
        $c3 = Start-Boxed $cmd @('/c', "type `"$secret`"") $box.Root $envPairs 512 $cred
        try { $code3 = $c3.Wait() } finally { $c3.Dispose() }
        $ok3 = ($code3 -ne 0)
        Write-Host ("[4/5] read your profile blocked {0} (exit {1})" -f $(if ($ok3) { 'PASS' } else { 'FAIL' }), $code3)
        if (-not $ok3) { $okAll = $false }
    }
    else {
        Write-Host '[4/5] read your profile blocked SKIP (no separate account)'
    }

    # The job object must actually enforce the ceiling. Allocating 800 MB inside a
    # 512 MB box has to fail; the child returns 7 on allocation failure, 0 if the
    # cap is not enforced.
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $probe = 'try { $x = New-Object byte[] 800MB; exit 0 } catch { exit 7 }'
    $c4 = Start-Boxed $ps @('-NoProfile', '-Command', $probe) $box.Root $envPairs 512 $cred
    try { $code4 = $c4.Wait() } finally { $c4.Dispose() }
    $ok4 = ($code4 -eq 7)
    Write-Host ("[5/5] memory cap enforced .... {0} (exit {1})" -f $(if ($ok4) { 'PASS' } else { 'FAIL' }), $code4)
    if (-not $ok4) { $okAll = $false }

    Remove-Item -LiteralPath $outside -Force -ErrorAction SilentlyContinue
    [void](Remove-Box $box.Root)

    if ($okAll) { Write-Host 'RESULT: PASS' }
    else { Write-Host 'RESULT: FAIL'; throw 'self-test failed' }
}

function Invoke-Gui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $bgDark    = [System.Drawing.Color]::FromArgb(15, 17, 26)
    $bgCard    = [System.Drawing.Color]::FromArgb(24, 28, 42)
    $bgInput   = [System.Drawing.Color]::FromArgb(32, 38, 56)
    $fgText    = [System.Drawing.Color]::FromArgb(226, 232, 240)
    $fgMuted   = [System.Drawing.Color]::FromArgb(148, 163, 184)
    $accIndigo = [System.Drawing.Color]::FromArgb(99, 102, 241)
    $accGreen  = [System.Drawing.Color]::FromArgb(16, 185, 129)
    $accRed    = [System.Drawing.Color]::FromArgb(239, 68, 68)
    $accSlate  = [System.Drawing.Color]::FromArgb(51, 65, 85)
    $accAmber  = [System.Drawing.Color]::FromArgb(245, 158, 11)

    $fontTitle = New-Object System.Drawing.Font('Segoe UI Semibold', 15)
    $fontHero  = New-Object System.Drawing.Font('Segoe UI Semibold', 12)
    $fontSub   = New-Object System.Drawing.Font('Segoe UI', 9)
    $fontBold  = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
    $fontNorm  = New-Object System.Drawing.Font('Segoe UI', 9.5)
    $fontMono  = New-Object System.Drawing.Font('Consolas', 9)

    $collapsedHeight = 338
    $expandedHeight  = 665

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Hermes Box - Disposable Browser Sandbox'
    $form.Size = New-Object System.Drawing.Size(700, $collapsedHeight)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedSingle'
    $form.MaximizeBox = $false
    $form.BackColor = $bgDark
    $form.ForeColor = $fgText

    # 1. Header panel
    $hdr = New-Object System.Windows.Forms.Panel
    $hdr.SetBounds(16, 12, 652, 58)
    $hdr.BackColor = $bgCard
    $form.Controls.Add($hdr)

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = 'HERMES BOX'
    $lblTitle.Font = $fontTitle
    $lblTitle.ForeColor = $fgText
    $lblTitle.SetBounds(16, 6, 260, 26)
    $hdr.Controls.Add($lblTitle)

    $lblSub = New-Object System.Windows.Forms.Label
    $lblSub.Text = 'SquareX-Style Isolated Browser  |  Zero-Persistence Chrome Sandbox'
    $lblSub.Font = $fontSub
    $lblSub.ForeColor = $fgMuted
    $lblSub.SetBounds(18, 33, 410, 18)
    $hdr.Controls.Add($lblSub)

    $credInit = Get-AccountCredential
    $lblBadge = New-Object System.Windows.Forms.Label
    $lblBadge.Font = $fontBold
    $lblBadge.TextAlign = 'MiddleCenter'
    $lblBadge.SetBounds(430, 14, 206, 30)
    if ($credInit) {
        $lblBadge.Text = "ACCOUNT MODE: $($credInit.User)"
        $lblBadge.BackColor = [System.Drawing.Color]::FromArgb(16, 78, 58)
        $lblBadge.ForeColor = $accGreen
    }
    else {
        $lblBadge.Text = 'TOKEN MODE (No File Boundary)'
        $lblBadge.BackColor = [System.Drawing.Color]::FromArgb(78, 52, 16)
        $lblBadge.ForeColor = $accAmber
    }
    $hdr.Controls.Add($lblBadge)

    # 2. Hero 1-Click Launch Card (No URL or config needed!)
    $hero = New-Object System.Windows.Forms.Panel
    $hero.SetBounds(16, 78, 652, 114)
    $hero.BackColor = $bgCard
    $form.Controls.Add($hero)

    $btnLaunch = New-Object System.Windows.Forms.Button
    $btnLaunch.Text = 'Launch Disposable Browser (1-Click Instant Start)'
    $btnLaunch.Font = $fontHero
    $btnLaunch.FlatStyle = 'Flat'
    $btnLaunch.BackColor = $accIndigo
    $btnLaunch.ForeColor = [System.Drawing.Color]::White
    $btnLaunch.FlatAppearance.BorderSize = 0
    $btnLaunch.SetBounds(16, 14, 444, 48)
    $hero.Controls.Add($btnLaunch)

    $btnNuke = New-Object System.Windows.Forms.Button
    $btnNuke.Text = 'Nuke / Kill Session'
    $btnNuke.Font = $fontBold
    $btnNuke.FlatStyle = 'Flat'
    $btnNuke.BackColor = $accRed
    $btnNuke.ForeColor = [System.Drawing.Color]::White
    $btnNuke.FlatAppearance.BorderSize = 0
    $btnNuke.Enabled = $false
    $btnNuke.SetBounds(472, 14, 164, 48)
    $hero.Controls.Add($btnNuke)

    $chkUblock = New-Object System.Windows.Forms.CheckBox
    $chkUblock.Text = 'uBlock Origin (Always On)'
    $chkUblock.Font = $fontBold
    $chkUblock.ForeColor = $accGreen
    $chkUblock.Checked = $true
    $chkUblock.Enabled = $false
    $chkUblock.SetBounds(18, 74, 185, 24)
    $hero.Controls.Add($chkUblock)

    $chkVpn = New-Object System.Windows.Forms.CheckBox
    $chkVpn.Text = '1ClickVPN Proxy'
    $chkVpn.Font = $fontBold
    $chkVpn.ForeColor = $fgText
    $chkVpn.Checked = $true
    $chkVpn.SetBounds(208, 74, 140, 24)
    $hero.Controls.Add($chkVpn)

    $chkAuto = New-Object System.Windows.Forms.CheckBox
    $chkAuto.Text = 'Auto-Scale RAM (2.5-4 GB)'
    $chkAuto.Font = $fontNorm
    $chkAuto.ForeColor = $fgMuted
    $chkAuto.Checked = $true
    $chkAuto.SetBounds(350, 74, 185, 24)
    $hero.Controls.Add($chkAuto)

    $btnAdv = New-Object System.Windows.Forms.Button
    $btnAdv.Text = 'Advanced v'
    $btnAdv.Font = $fontSub
    $btnAdv.FlatStyle = 'Flat'
    $btnAdv.BackColor = $accSlate
    $btnAdv.ForeColor = $fgText
    $btnAdv.FlatAppearance.BorderSize = 0
    $btnAdv.SetBounds(542, 72, 94, 26)
    $hero.Controls.Add($btnAdv)

    # 3. Live Telemetry Panel
    $tel = New-Object System.Windows.Forms.Panel
    $tel.SetBounds(16, 200, 652, 82)
    $tel.BackColor = $bgCard
    $form.Controls.Add($tel)

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text = 'STATUS: IDLE - Click Launch above (no URL required; control tabs & VPN inside browser)'
    $lblStatus.Font = $fontBold
    $lblStatus.ForeColor = $accGreen
    $lblStatus.SetBounds(16, 10, 620, 22)
    $tel.Controls.Add($lblStatus)

    $lblRam = New-Object System.Windows.Forms.Label
    $lblRam.Text = 'Commit: 0 MB / Auto (2560-4096 MB)   |   Working Set: 0 MB   |   Processes: 0'
    $lblRam.Font = $fontSub
    $lblRam.ForeColor = $fgMuted
    $lblRam.SetBounds(16, 34, 620, 20)
    $tel.Controls.Add($lblRam)

    $barBg = New-Object System.Windows.Forms.Panel
    $barBg.SetBounds(16, 58, 620, 12)
    $barBg.BackColor = $bgInput
    $tel.Controls.Add($barBg)

    $barFill = New-Object System.Windows.Forms.Panel
    $barFill.SetBounds(0, 0, 0, 12)
    $barFill.BackColor = $accIndigo
    $barBg.Controls.Add($barFill)

    # 4. Collapsible Advanced Drawer (hidden by default for clean 1-click UX)
    $adv = New-Object System.Windows.Forms.Panel
    $adv.SetBounds(16, 292, 652, 320)
    $adv.BackColor = $bgCard
    $adv.Visible = $false
    $form.Controls.Add($adv)

    $lblUrl = New-Object System.Windows.Forms.Label
    $lblUrl.Text = 'Optional Pre-Launch URL(s) (leave empty to open In-Browser Hermes Dashboard):'
    $lblUrl.Font = $fontBold
    $lblUrl.ForeColor = $fgText
    $lblUrl.SetBounds(16, 10, 520, 20)
    $adv.Controls.Add($lblUrl)

    $txtUrl = New-Object System.Windows.Forms.TextBox
    $txtUrl.Text = ''
    $txtUrl.Font = $fontNorm
    $txtUrl.BackColor = $bgInput
    $txtUrl.ForeColor = $fgText
    $txtUrl.BorderStyle = 'FixedSingle'
    $txtUrl.SetBounds(16, 32, 620, 25)
    $adv.Controls.Add($txtUrl)

    $chips = @(
        @{ Label = 'Dashboard (Default)'; Url = '' },
        @{ Label = 'YouTube'; Url = 'https://www.youtube.com' },
        @{ Label = 'Google';  Url = 'https://www.google.com' },
        @{ Label = '5-Tab Mix'; Url = 'https://www.youtube.com,https://en.wikipedia.org,https://github.com,https://news.ycombinator.com,https://example.com' }
    )
    $chipX = 16
    foreach ($c in $chips) {
        $btnChip = New-Object System.Windows.Forms.Button
        $btnChip.Text = $c.Label
        $btnChip.Tag = $c.Url
        $btnChip.Font = $fontSub
        $btnChip.FlatStyle = 'Flat'
        $btnChip.BackColor = $accSlate
        $btnChip.ForeColor = $fgText
        $btnChip.FlatAppearance.BorderSize = 0
        $btnChip.SetBounds($chipX, 62, 130, 23)
        $btnChip.Add_Click({ param($s, $e) $txtUrl.Text = [string]$s.Tag })
        $adv.Controls.Add($btnChip)
        $chipX += 136
    }

    $lblPreset = New-Object System.Windows.Forms.Label
    $lblPreset.Text = 'RAM Ceiling Mode:'
    $lblPreset.Font = $fontBold
    $lblPreset.SetBounds(16, 94, 230, 18)
    $adv.Controls.Add($lblPreset)

    $cmbPreset = New-Object System.Windows.Forms.ComboBox
    $cmbPreset.Font = $fontNorm
    $cmbPreset.BackColor = $bgInput
    $cmbPreset.ForeColor = $fgText
    $cmbPreset.DropDownStyle = 'DropDownList'
    $cmbPreset.FlatStyle = 'Flat'
    [void]$cmbPreset.Items.Add('Auto-Optimize (Dynamic 2560 - 4096 MB)')
    [void]$cmbPreset.Items.Add('Standard Fixed - 2560 MB Ceiling')
    [void]$cmbPreset.Items.Add('Ultra Low-RAM - 1536 MB Ceiling (4 Renderers)')
    [void]$cmbPreset.Items.Add('Heavy Multi-Tab - 3584 MB Ceiling')
    $cmbPreset.SelectedIndex = 0
    $cmbPreset.SetBounds(16, 114, 270, 25)
    $adv.Controls.Add($cmbPreset)

    $lblEngine = New-Object System.Windows.Forms.Label
    $lblEngine.Text = 'Engine:'
    $lblEngine.Font = $fontBold
    $lblEngine.SetBounds(298, 94, 110, 18)
    $adv.Controls.Add($lblEngine)

    $cmbEngine = New-Object System.Windows.Forms.ComboBox
    $cmbEngine.Font = $fontNorm
    $cmbEngine.BackColor = $bgInput
    $cmbEngine.ForeColor = $fgText
    $cmbEngine.DropDownStyle = 'DropDownList'
    $cmbEngine.FlatStyle = 'Flat'
    [void]$cmbEngine.Items.Add('Auto - Google Chrome (Default)')
    [void]$cmbEngine.Items.Add('Google Chrome')
    [void]$cmbEngine.Items.Add('Brave Browser')
    [void]$cmbEngine.Items.Add('Microsoft Edge')
    $cmbEngine.SelectedIndex = 0
    $cmbEngine.SetBounds(298, 114, 175, 25)
    $adv.Controls.Add($cmbEngine)

    $chkKeep = New-Object System.Windows.Forms.CheckBox
    $chkKeep.Text = 'Keep Box on Exit'
    $chkKeep.Font = $fontNorm
    $chkKeep.Checked = $false
    $chkKeep.SetBounds(488, 114, 140, 24)
    $adv.Controls.Add($chkKeep)

    $lblDl = New-Object System.Windows.Forms.Label
    $lblDl.Text = 'Quarantine Downloads Folder:'
    $lblDl.Font = $fontSub
    $lblDl.ForeColor = $fgMuted
    $lblDl.SetBounds(16, 146, 220, 18)
    $adv.Controls.Add($lblDl)

    $txtDl = New-Object System.Windows.Forms.TextBox
    $txtDl.Text = (Join-Path $env:USERPROFILE 'Downloads\HermesBox-Quarantine')
    $txtDl.Font = $fontNorm
    $txtDl.BackColor = $bgInput
    $txtDl.ForeColor = $fgText
    $txtDl.BorderStyle = 'FixedSingle'
    $txtDl.SetBounds(16, 165, 270, 24)
    $adv.Controls.Add($txtDl)

    $lblProxy = New-Object System.Windows.Forms.Label
    $lblProxy.Text = 'Custom SOCKS5/HTTP Proxy:'
    $lblProxy.Font = $fontSub
    $lblProxy.ForeColor = $fgMuted
    $lblProxy.SetBounds(298, 146, 200, 18)
    $adv.Controls.Add($lblProxy)

    $txtProxy = New-Object System.Windows.Forms.TextBox
    $txtProxy.Text = ''
    $txtProxy.Font = $fontNorm
    $txtProxy.BackColor = $bgInput
    $txtProxy.ForeColor = $fgText
    $txtProxy.BorderStyle = 'FixedSingle'
    $txtProxy.SetBounds(298, 165, 175, 24)
    $adv.Controls.Add($txtProxy)

    $btnTest = New-Object System.Windows.Forms.Button
    $btnTest.Text = 'Self-Test'
    $btnTest.Font = $fontSub
    $btnTest.FlatStyle = 'Flat'
    $btnTest.BackColor = $accGreen
    $btnTest.ForeColor = [System.Drawing.Color]::White
    $btnTest.FlatAppearance.BorderSize = 0
    $btnTest.SetBounds(484, 163, 74, 26)
    $adv.Controls.Add($btnTest)

    $btnWipe = New-Object System.Windows.Forms.Button
    $btnWipe.Text = 'Wipe All'
    $btnWipe.Font = $fontSub
    $btnWipe.FlatStyle = 'Flat'
    $btnWipe.BackColor = $accSlate
    $btnWipe.ForeColor = $fgText
    $btnWipe.FlatAppearance.BorderSize = 0
    $btnWipe.SetBounds(564, 163, 72, 26)
    $adv.Controls.Add($btnWipe)

    $txtLog = New-Object System.Windows.Forms.TextBox
    $txtLog.Multiline = $true
    $txtLog.ReadOnly = $true
    $txtLog.ScrollBars = 'Vertical'
    $txtLog.Font = $fontMono
    $txtLog.BackColor = [System.Drawing.Color]::FromArgb(10, 12, 18)
    $txtLog.ForeColor = [System.Drawing.Color]::FromArgb(167, 243, 208)
    $txtLog.BorderStyle = 'FixedSingle'
    $txtLog.SetBounds(16, 198, 620, 108)
    $adv.Controls.Add($txtLog)

    $btnAdv.Add_Click({
        $adv.Visible = (-not $adv.Visible)
        if ($adv.Visible) {
            $form.Size = New-Object System.Drawing.Size(700, $expandedHeight)
            $btnAdv.Text = 'Advanced ^'
        }
        else {
            $form.Size = New-Object System.Drawing.Size(700, $collapsedHeight)
            $btnAdv.Text = 'Advanced v'
        }
    })

    $state = [hashtable]::Synchronized(@{
        Child      = $null
        Box        = $null
        CapMb      = 2560
        AutoScale  = $true
        DlDir      = $null
        Keep       = $false
        ProcName   = 'chrome'
        Baseline   = @()
    })

    $appendLog = {
        param([string]$msg)
        $ts = Get-Date -Format 'HH:mm:ss'
        $txtLog.AppendText("[$ts] $msg`r`n")
    }

    & $appendLog "Hermes Box v0.3.0 Auto-Optimizer ready. Data dir: $script:HermesHome"
    if ($credInit) { & $appendLog "Account mode active: running isolated as local user '$($credInit.User)'." }

    $syncInitJson = {
        $modeStr = if ($credInit) { "Account Mode ($($credInit.User))" } else { 'Token Mode' }
        $capStr  = if ($chkAuto.Checked) { "Auto-Scale ($($state.CapMb) MB)" } else { "Fixed $($state.CapMb) MB" }
        Set-ControllerInitState $chkUblock.Checked $chkVpn.Checked $modeStr $capStr
    }
    $chkUblock.Add_CheckedChanged($syncInitJson)
    $chkVpn.Add_CheckedChanged($syncInitJson)
    $chkAuto.Add_CheckedChanged({
        $state.AutoScale = $chkAuto.Checked
        if ($chkAuto.Checked) { $cmbPreset.SelectedIndex = 0 }
        & $syncInitJson
    })
    $cmbPreset.Add_SelectedIndexChanged({
        $chkAuto.Checked = ($cmbPreset.SelectedIndex -eq 0)
        $state.AutoScale = $chkAuto.Checked
        if (-not $state.AutoScale) {
            $newCap = switch ($cmbPreset.SelectedIndex) {
                1 { 2560 }
                2 { 1536 }
                3 { 3584 }
                default { 2560 }
            }
            $state.CapMb = $newCap
            if ($state.Child) {
                $state.Child.UpdateCap([int64]$newCap * 1024L * 1024L)
                & $appendLog "Live updated Job Object ceiling -> $newCap MB"
            }
        }
    })

    $finishSession = {
        param([string]$reason)
        if ($state.Child) {
            try { $state.Child.Dispose() } catch { }
            $state.Child = $null
        }
        if ($state.Box) {
            $b = $state.Box
            $state.Box = $null
            if ($state.DlDir) {
                $savedN = Save-QuarantineDownloads $b.Root $state.DlDir
                if ($savedN -gt 0) {
                    & $appendLog "Saved $savedN downloaded file(s) -> $($state.DlDir) (Mark-of-the-Web applied)"
                }
            }
            if ($state.Keep) {
                Add-Content -LiteralPath (Join-Path $b.Root 'meta.txt') -Value 'keep=1' -Encoding ASCII
                & $appendLog "Session ended ($reason). Box kept at: $($b.Root)"
            }
            else {
                if (Remove-Box $b.Root) { & $appendLog "Session ended ($reason). Box $($b.Id) wiped cleanly (0 B left)." }
                else { & $appendLog "Session ended ($reason). Box $($b.Id) queued for deferred sweep." }
            }
        }
        $lblStatus.Text = 'STATUS: IDLE - Click Launch above (no URL required; control tabs & VPN inside browser)'
        $lblStatus.ForeColor = $accGreen
        $lblRam.Text = 'Commit: 0 MB / Auto (2560-4096 MB)   |   Working Set: 0 MB   |   Processes: 0'
        $barFill.Width = 0
        $btnLaunch.Enabled = $true
        $btnNuke.Enabled = $false
    }

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1200
    $timer.Add_Tick({
        if (-not $state.Child) { return }
        if ($state.Child.WaitTimeout(0)) {
            & $finishSession 'browser closed'
            return
        }
        $procs = @(Get-Process -Name $state.ProcName -ErrorAction SilentlyContinue |
            Where-Object { $state.Baseline -notcontains $_.Id })
        $wsMb = [math]::Round((($procs | Measure-Object -Property WorkingSet64 -Sum).Sum / 1MB), 0)
        $commitMb = [math]::Round((($procs | Measure-Object -Property PrivateMemorySize64 -Sum).Sum / 1MB), 0)

        # Dynamic Auto-Scaler: adjusts Job Object memory limit live based on active tab/process pressure
        if ($state.AutoScale) {
            $targetCap = if ($commitMb -ge 2200 -or $procs.Count -ge 18) { 4096 }
                         elseif ($commitMb -ge 1600 -or $procs.Count -ge 14) { 3072 }
                         else { 2560 }
            if ($targetCap -ne $state.CapMb) {
                $state.CapMb = $targetCap
                $state.Child.UpdateCap([int64]$targetCap * 1024L * 1024L)
                & $appendLog "Auto-Scaler adjusted Job ceiling -> $targetCap MB (Commit: $commitMb MB, Procs: $($procs.Count))"
            }
        }

        $pct = [math]::Min(100, [math]::Round(($commitMb * 100.0) / [math]::Max(1, $state.CapMb), 0))
        $scaleTag = if ($state.AutoScale) { 'Auto' } else { 'Fixed' }
        $lblRam.Text = "Commit: $commitMb MB / $($state.CapMb) MB [$scaleTag] ($pct%)   |   Working Set: $wsMb MB   |   Procs: $($procs.Count)"
        $barFill.Width = [int]([math]::Round(620 * ($pct / 100.0)))
        if ($pct -ge 85) { $barFill.BackColor = $accRed }
        elseif ($pct -ge 65) { $barFill.BackColor = $accAmber }
        else { $barFill.BackColor = $accIndigo }
    })
    $timer.Start()

    $btnLaunch.Add_Click({
        if ($state.Child) { return }
        try {
            $engName = switch ($cmbEngine.SelectedIndex) {
                1 { 'chrome' }
                2 { 'brave' }
                3 { 'edge' }
                default { 'auto' }
            }
            $exe = Resolve-Browser $engName
            $procName = if ($exe -match 'msedge\.exe$') { 'msedge' } elseif ($exe -match 'brave\.exe$') { 'brave' } else { 'chrome' }
            $cred = Get-AccountCredential
            $isAuto = ($chkAuto.Checked -or $cmbPreset.SelectedIndex -eq 0)
            $isLowRam = ($cmbPreset.SelectedIndex -eq 2)
            $cap = if ($isAuto) { 2560 } else {
                switch ($cmbPreset.SelectedIndex) {
                    1 { 2560 }
                    2 { 1536 }
                    3 { 3584 }
                    default { 2560 }
                }
            }
            $rawUrls = @($txtUrl.Text -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

            $dlTarget = $null
            if ($txtDl.Text.Trim()) {
                $dlTarget = $txtDl.Text.Trim()
                New-Item -ItemType Directory -Force -Path $dlTarget | Out-Null
            }

            $state.ProcName = $procName
            $state.AutoScale = $isAuto
            $state.CapMb = $cap
            & $syncInitJson

            $state.Baseline = @(Get-Process -Name $procName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
            $box = New-Box $cap $(if ($cred) { $cred.User } else { $null }) $null $rawUrls
            $envPairs = Get-EnvPairs $box.Root
            $bargs = Get-BrowserArgs $box.Root $null $rawUrls $null $txtProxy.Text.Trim() $isLowRam $false @() $exe $false

            & $appendLog "Launching $($box.Id) on $engName (uBlock=AlwaysOn, 1ClickVPN=$($chkVpn.Checked), AutoScale=$isAuto)..."
            $child = Start-Boxed $exe $bargs $box.Root $envPairs $cap $cred

            $state.Child = $child
            $state.Box   = $box
            $state.DlDir = $dlTarget
            $state.Keep  = $chkKeep.Checked

            $lblStatus.Text = "ACTIVE: $($box.Id) (PID $($child.Pid)) - Toggle VPN or open tabs inside browser"
            $lblStatus.ForeColor = $accAmber
            $btnLaunch.Enabled = $false
            $btnNuke.Enabled = $true
            & $appendLog "Started PID $($child.Pid) inside $($box.Root)"
        }
        catch {
            & $appendLog "ERROR: $($_.Exception.Message)"
        }
    })

    $btnNuke.Add_Click({
        if ($state.Child) {
            & $appendLog 'Nuking active sandbox job and wiping box...'
            & $finishSession 'nuked by user'
        }
    })

    $btnTest.Add_Click({
        $btnTest.Enabled = $false
        & $appendLog 'Running 5-step containment & memory cap self-test...'
        $form.Refresh()
        try {
            $out = & $PSCommandPath selftest 2>&1 | Out-String
            foreach ($line in ($out -split "`r?`n")) {
                if ($line.Trim()) { & $appendLog "  $line" }
            }
        }
        catch {
            & $appendLog "Self-test error: $($_.Exception.Message)"
        }
        finally {
            $btnTest.Enabled = $true
        }
    })

    $btnWipe.Add_Click({
        & $appendLog 'Wiping all inactive boxes...'
        try {
            $out = & $PSCommandPath wipe -All 2>&1 | Out-String
            foreach ($line in ($out -split "`r?`n")) {
                if ($line.Trim()) { & $appendLog "  $line" }
            }
        }
        catch {
            & $appendLog "Wipe error: $($_.Exception.Message)"
        }
    })

    $form.Add_FormClosing({
        $timer.Stop()
        if ($state.Child) {
            & $finishSession 'GUI closed'
        }
    })

    $form.Add_Shown({
        $form.TopMost = $true
        $form.Activate()
        $form.TopMost = $false
        $form.Refresh()
        Ensure-Native
        if ($HideConsole) {
            try { [HermesNative]::HideConsole() } catch { }
        }
    })

    [void]$form.ShowDialog()
}

function Show-Help {
    Write-Host @'
Hermes Box - a featherweight, disposable Chromium sandbox for Windows.

USAGE:
  hermesbox       (or hermesbox gui)   Open the dark-themed GUI Control Center
  hermesbox run   [-Url URL] [-Urls URL1,URL2] [-CapMb N] [-LowRam] [-Private]
                  [-Browser edge|chrome|path] [-Extension DIR] [-Proxy URL]
                  [-Downloads DIR] [-TimeoutSec N] [-Keep]
  hermesbox list
  hermesbox wipe  <ID> | -All
  hermesbox info
  hermesbox selftest

OPTIONS:
  -CapMb N        Hard memory ceiling for the whole tree (default 1536 MB)
  -LowRam         Ultra-light preset (900 MB cap, 2 renderers, 256 MB V8 heap)
  -Private        Launch in InPrivate / Incognito mode inside the box
  -Proxy URL      Route traffic through proxy (e.g. socks5://127.0.0.1:1080) with DNS leak block
  -Downloads DIR  Save downloads to DIR instead of wiping them with the box

MODES:
  account mode    enabled automatically after setup-account.ps1 (elevated).
                  Real SID isolation: the browser cannot read or write your profile.
  token mode      fallback with no admin. Blocks elevation and caps memory, but the
                  process still runs as you (not a filesystem boundary).

ENV:
  HERMESBOX_HOME        Override the data directory (default %LOCALAPPDATA%\HermesBox)
  HERMESBOX_EXTRA       Extra browser flags, space separated
  HERMESBOX_FORCE_TOKEN Force token mode even if the account exists
'@
}

$cmd = $Command.ToLowerInvariant()
if ($cmd -notin @('help', '-h', '--help', 'version')) {
    Invoke-Sweep
}

switch ($cmd) {
    'gui' { Invoke-Gui }
    'ui' { Invoke-Gui }
    'run' { Invoke-Run }
    'list' { Invoke-List }
    'ls' { Invoke-List }
    'wipe' { Invoke-Wipe }
    'rm' { Invoke-Wipe }
    'info' { Invoke-Info }
    'selftest' { Invoke-SelfTest }
    'help' { Show-Help }
    '-h' { Show-Help }
    '--help' { Show-Help }
    'version' { Write-Host 'hermesbox 0.2.0 (powershell host)' }
    default { Write-Host "unknown command: $Command`n"; Show-Help; exit 2 }
}

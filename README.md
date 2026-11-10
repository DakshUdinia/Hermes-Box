# Hermes Box

A featherweight, disposable browser sandbox for Windows 10/11. It runs **Google Chrome** (with automatic fallback to Brave, Chromium, or Microsoft Edge) inside a memory-capped Win32 Job Object with an ephemeral profile, embedded **uBlock Origin** (always on) + **1ClickVPN Proxy** (one-click toggle), and a dedicated local Windows account (`HermesBox`) for real SID-level filesystem isolation.

No VM. No kernel driver. No Electron. No subscription. No timer.

```
hermesbox  ->  box-<timestamp>  ->  Chrome in an isolated Job Object  ->  wiped to 0 bytes on exit
```

### Benchmark Footprint (Windows 11)

| State | Processes | Working Set | Commit Charge | Job Ceiling |
|---|---|---|---|---|
| 1 Tab (Standard Mode) | 9–14 | **365–585 MB** | **165–275 MB** | Auto (`2560–4096 MB`) |
| 5 Tabs + 1080p60 YouTube | 13–21 | **860–1280 MB** | **690–860 MB** | Auto (`2560–4096 MB`) |
| Disk After Closing Browser | 0 | **0 MB** | **0 MB** | **0 Bytes Left on Disk** |

---

## Key Features

- **Google Chrome Default Engine (+ Auto-Fallback):** Uses your existing Google Chrome installation (`Program Files` or `%LOCALAPPDATA%`) with zero duplicate browser binary download. Automatically falls back to Brave, Chromium, or Microsoft Edge if Chrome is not installed.
- **Bundled Privacy & Adblock Extensions (Works Out-of-the-Box):**
  - **uBlock Origin (Always On):** Embedded inside every disposable sandbox session and locked on automatically.
  - **1ClickVPN Proxy:** Embedded inside the sandbox; toggleable both before launch (from the GUI or Chrome extension) and live inside the sandbox.
  - **In-Sandbox Control Center (`chrome://newtab`):** Dark-mode dashboard + toolbar popup with selective multi-tab launcher, live VPN toggle, and a **Panic Wipe** button that closes and wipes the entire session in milliseconds.
- **Daily Chrome Companion Extension ("Send Tabs to Hermes Box"):**
  - Automatically installed and pinned to your daily Google Chrome toolbar (`H` icon).
  - Send selected open tabs, right-clicked links, or launch a fresh empty sandbox directly from Chrome in 1 click.
- **Always Dark Mode:** Forces dark UI and web content (`--force-dark-mode` + dark theme preferences + sandbox registry personalization).
- **Two Isolation Modes:**
  - **Account Mode (Recommended):** Runs the sandboxed browser as a separate non-admin local Windows user (`HermesBox`) via `CreateProcessWithLogonW`. Real SID-level isolation — the browser **cannot read or write your personal `C:\Users\<you>` profile or secondary drives (`D:`, `E:`, `F:`)**.
  - **Token Mode (Zero-Admin Fallback):** Uses `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` + Job Object memory cap + ephemeral profile when run without administrator privileges.

---

## One-Click Installation

Clone or download this repository and double-click **`setup.cmd`** (or run in PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

### What the Setup Wizard Does Automatically
1. Installs the `hermesbox` CLI and **Hermes Box Control Center GUI** into `%LOCALAPPDATA%\HermesBox\bin` and adds Desktop + Start Menu shortcuts.
2. Deploys the bundled **uBlock Origin**, **1ClickVPN Proxy**, and **Sandbox Control Center** extensions into `C:\ProgramData\HermesBox\extensions`.
3. Installs and pins the **Hermes Box Companion Extension** into your daily Google Chrome (and Brave) browser and registers the Native Messaging bridge (`com.hermesbox.bridge`).
4. Prompts once via UAC to provision the isolated `HermesBox` Windows account (hidden from the Windows sign-in screen, blocked from network/RDP logon, and denied access to your personal profile and secondary drives) and runs the **5-step self-test**.

---

## Usage

### 1. From Your Daily Google Chrome Browser
Click the pinned **H** (**Hermes Box**) icon on your Chrome toolbar:
- **⚡ Launch Fresh Empty Sandbox** — Opens an isolated disposable Chrome session immediately.
- **🚀 Open Selected Tabs in Sandbox** — Pick any open tabs from your daily browser and move them into the sandbox.
- **🎛️ Open Hermes Box Control Center** — Opens the native dark-themed desktop Control Center GUI.
- **Right-Click Any Link or Page** → **🛡️ Open Link in Hermes Box Sandbox**.

### 2. From the Desktop / Start Menu GUI
Double-click **Hermes Box** on your Desktop or Start Menu to open the native WinForms Control Center (~20 MB RAM, zero Electron) with live RAM telemetry, 1ClickVPN toggle, and 1-click **Launch** / **Nuke & Wipe**.

### 3. From Terminal (`hermesbox`)

```powershell
hermesbox                        # Open the GUI Control Center
hermesbox run                    # Launch a fresh disposable sandbox
hermesbox run -Url https://example.com
hermesbox run -Urls https://youtube.com,https://github.com,https://news.ycombinator.com
hermesbox run -Url https://example.com -LowRam -Private
hermesbox run -Url https://example.com -Downloads "$HOME\Downloads\Quarantine"
hermesbox selftest               # Run the 5-step isolation & memory-cap verification
hermesbox info                   # Show detected browsers and active isolation mode
hermesbox list                   # List active sandbox sessions
hermesbox wipe -All              # Sweep all sandbox directories
```

---

## Repository Layout

```
setup.cmd                   One-click setup wizard entrypoint
scripts/
  hermes.ps1                Main launcher, Win32 P/Invoke Job/Token/Account engine & GUI
  install.ps1               Automated installer, Chrome extension patcher & setup wizard
  setup-account.ps1         Elevated local account provisioning & drive ACL lockdown
  native-host.ps1           Chrome Native Messaging bridge (com.hermesbox.bridge)
extensions/
  controller/               In-sandbox Control Center dashboard (chrome://newtab) & popup
  ublock/                   Bundled standalone uBlock Origin (Always On in sandbox)
  vpn/                      Bundled standalone 1ClickVPN Proxy
  companion/                Companion extension for daily Google Chrome ("Send to Sandbox")
src/                        Native Rust implementation (hermes.exe)
Cargo.toml
```

---

## Uninstall

```powershell
# Remove per-user CLI, shortcuts, and registry entries
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\HermesBox\bin\install.ps1" -Uninstall

# Remove the HermesBox local Windows account and shared files (elevated)
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\HermesBox\bin\setup-account.ps1" -Remove
```

## License

MIT License. Google Chrome, Microsoft Edge, uBlock Origin, and 1ClickVPN remain under their respective upstream licenses.

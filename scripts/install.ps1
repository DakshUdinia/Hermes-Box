#Requires -Version 5.1
<#
.SYNOPSIS
  Per-user installer for Hermes Box.

.DESCRIPTION
  Copies the launcher into %LOCALAPPDATA%\Hermes\bin, adds it to your user PATH,
  writes a hermes.cmd shim (pwsh with a Windows PowerShell fallback), and creates
  a Start Menu shortcut.

  Account mode (full isolation) still needs one elevated run of
  setup-account.ps1 - the installer will tell you.

.EXAMPLE
  .\install.ps1
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$SkipAccountSetup,
    [switch]$SkipChromePatch
)

$ErrorActionPreference = 'Stop'
$src = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent $src
$homeDir = if ($env:HERMESBOX_HOME) { $env:HERMESBOX_HOME } else { Join-Path $env:LOCALAPPDATA 'HermesBox' }
$bin = Join-Path $homeDir 'bin'
$link = Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Hermes Box.lnk'
$deskLink = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Hermes Box.lnk'

if ($Uninstall) {
    Remove-Item -LiteralPath $link -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $deskLink -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $bin -Recurse -Force -ErrorAction SilentlyContinue
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -and $userPath.Contains($bin)) {
        $newPath = (($userPath -split ';') | Where-Object { $_ -and $_ -ne $bin }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    }
    Write-Host 'Hermes Box uninstalled (boxes in %LOCALAPPDATA%\HermesBox\boxes were left alone).'
    Write-Host 'Run setup-account.ps1 -Remove elevated to remove the sandbox account.'
    return
}

Write-Host '=== Hermes Box Setup Wizard (Chrome Default Edition) ===' -ForegroundColor Cyan

try {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force -ErrorAction SilentlyContinue
} catch { }

New-Item -ItemType Directory -Force -Path $bin | Out-Null
Copy-Item -LiteralPath (Join-Path $src 'hermes.ps1') -Destination (Join-Path $bin 'hermes.ps1') -Force
Remove-Item -LiteralPath (Join-Path $bin 'hermesbox.ps1') -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $bin 'hermesbox.exe') -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath (Join-Path $src 'setup-account.ps1') -Destination (Join-Path $bin 'setup-account.ps1') -Force
if (Test-Path -LiteralPath (Join-Path $src 'install.ps1')) {
    Copy-Item -LiteralPath (Join-Path $src 'install.ps1') -Destination (Join-Path $bin 'install.ps1') -Force
}
if ($repoRoot -and (Test-Path -LiteralPath (Join-Path $repoRoot 'README.md'))) {
    Copy-Item -LiteralPath (Join-Path $repoRoot 'README.md') -Destination (Join-Path $homeDir 'README.md') -Force
}
$rustExe = if ($repoRoot) { Join-Path $repoRoot 'target\release\hermes.exe' } else { $null }
if ($rustExe -and (Test-Path -LiteralPath $rustExe)) {
    Copy-Item -LiteralPath $rustExe -Destination (Join-Path $homeDir 'hermesbox-native.exe') -Force
}

if (Test-Path -LiteralPath (Join-Path $src 'native-host.ps1')) {
    Copy-Item -LiteralPath (Join-Path $src 'native-host.ps1') -Destination (Join-Path $bin 'native-host.ps1') -Force
}

$nhShim = @'
@echo off
set "NH_SCRIPT=%LOCALAPPDATA%\HermesBox\bin\native-host.ps1"
where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%NH_SCRIPT%"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%NH_SCRIPT%"
)
'@
Set-Content -LiteralPath (Join-Path $bin 'native-host.cmd') -Value $nhShim -Encoding ASCII

$nhManifestPath = Join-Path $bin 'com.hermesbox.bridge.json'
$nhManifest = @{
    name = 'com.hermesbox.bridge'
    description = 'Hermes Box Native Messaging Bridge'
    path = (Join-Path $bin 'native-host.cmd')
    type = 'stdio'
    allowed_origins = @(
        'chrome-extension://nikijleckkplefnahnnjhlojmhjihlnb/',
        'chrome-extension://ajjibhjidlpbekdkdkkifhkiiibmkdnj/'
    )
} | ConvertTo-Json -Depth 4
Set-Content -LiteralPath $nhManifestPath -Value $nhManifest -Encoding ASCII

foreach ($regKey in @(
    'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.hermesbox.bridge',
    'HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.hermesbox.bridge',
    'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.hermesbox.bridge',
    'HKCU:\Software\Chromium\NativeMessagingHosts\com.hermesbox.bridge'
)) {
    New-Item -Path $regKey -Force | Out-Null
    Set-ItemProperty -Path $regKey -Name '(Default)' -Value $nhManifestPath -Force
}

# Deploy bundled sandbox extensions (controller, ublock, vpn) into C:\ProgramData\HermesBox\extensions
$sharedExtRoot = 'C:\ProgramData\HermesBox\extensions'
New-Item -ItemType Directory -Force -Path $sharedExtRoot | Out-Null
foreach ($extName in @('controller', 'ublock', 'vpn')) {
    $extSrc = if ($repoRoot) { Join-Path $repoRoot "extensions\$extName" } else { $null }
    if ($extSrc -and (Test-Path -LiteralPath $extSrc)) {
        $extDst = Join-Path $sharedExtRoot $extName
        if (Test-Path -LiteralPath $extDst) {
            Remove-Item -LiteralPath $extDst -Recurse -Force -ErrorAction SilentlyContinue
        }
        Copy-Item -LiteralPath $extSrc -Destination $extDst -Recurse -Force
    }
}
icacls.exe $sharedExtRoot /grant '*S-1-5-32-545:(OI)(CI)(RX)' /grant '*S-1-5-32-545:(RX)' /T /Q 2>$null | Out-Null
Write-Host '[1/4] Deployed bundled sandbox extensions (uBlock Origin, 1ClickVPN Proxy, Control Center).' -ForegroundColor Green

$compDst = Join-Path $homeDir 'companion-extension'
if ($repoRoot -and (Test-Path -LiteralPath (Join-Path $repoRoot 'extensions\companion'))) {
    if (Test-Path -LiteralPath $compDst) {
        Remove-Item -LiteralPath $compDst -Recurse -Force -ErrorAction SilentlyContinue
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'extensions\companion') -Destination $compDst -Recurse -Force
}

$shim = @'
@echo off
set "SCRIPT=%LOCALAPPDATA%\HermesBox\bin\hermes.ps1"
where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
)
'@
Set-Content -LiteralPath (Join-Path $bin 'hermesbox.cmd') -Value $shim -Encoding ASCII

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if (-not (($userPath -split ';') -contains $bin)) {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $bin).Trim(';'), 'User')
}

$ws = New-Object -ComObject WScript.Shell
$psHost = if (Get-Command pwsh -ErrorAction SilentlyContinue) { (Get-Command pwsh).Source } else { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }
$chromeExe = if (Test-Path "$env:ProgramFiles\Google\Chrome\Application\chrome.exe") {
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
} elseif (Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") {
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
} elseif (Test-Path "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") {
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
} else {
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
}

foreach ($lnkPath in @($link, $deskLink)) {
    $sc = $ws.CreateShortcut($lnkPath)
    $sc.TargetPath = $psHost
    $sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $bin 'hermes.ps1')`" gui -HideConsole"
    $sc.WorkingDirectory = $bin
    if (Test-Path -LiteralPath $chromeExe) { $sc.IconLocation = "$chromeExe,0" }
    $sc.Description = 'Hermes Box - Disposable Browser Sandbox Control Center'
    $sc.Save()
}
Write-Host "[2/4] Installed CLI ('hermesbox') and Desktop/Start Menu shortcuts." -ForegroundColor Green

# Auto-patch Chrome / Brave shortcuts & pin companion extension on toolbar
if (-not $SkipChromePatch -and (Test-Path -LiteralPath $compDst)) {
    $loadArg = "--load-extension=`"$compDst`""
    $lnkDirs = @(
        "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        ([Environment]::GetFolderPath('Desktop'))
    )
    foreach ($d in $lnkDirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        Get-ChildItem -LiteralPath $d -Filter '*.lnk' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $sc = $ws.CreateShortcut($_.FullName)
                if ($sc.TargetPath -match '(chrome|brave)\.exe$' -and $sc.Arguments -notlike '*companion-extension*') {
                    $sc.Arguments = ("$($sc.Arguments) $loadArg").Trim()
                    $sc.Save()
                }
            } catch { }
        }
    }

    foreach ($prefPath in @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Preferences"
    )) {
        if (Test-Path -LiteralPath $prefPath) {
            try {
                $raw = Get-Content -LiteralPath $prefPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if (-not $raw.extensions) {
                    $raw | Add-Member -NotePropertyName 'extensions' -NotePropertyValue ([pscustomobject]@{}) -Force
                }
                $pinned = @()
                if ($raw.extensions.pinned_extensions) {
                    $pinned = @($raw.extensions.pinned_extensions)
                }
                if ($pinned -notcontains 'nikijleckkplefnahnnjhlojmhjihlnb') {
                    $pinned = @('nikijleckkplefnahnnjhlojmhjihlnb') + $pinned
                    $raw.extensions | Add-Member -NotePropertyName 'pinned_extensions' -NotePropertyValue $pinned -Force
                    $jsonOut = $raw | ConvertTo-Json -Depth 32 -Compress
                    Set-Content -LiteralPath $prefPath -Value $jsonOut -Encoding UTF8
                }
            } catch { }
        }
    }
    Write-Host "[3/4] Configured Chrome/Brave companion extension & pinned toolbar badge." -ForegroundColor Green
}

# One-Command Account Mode Provisioning (triggers UAC if not already configured)
$accountFile = Join-Path $homeDir 'account.dat'
if (-not $SkipAccountSetup -and -not (Test-Path -LiteralPath $accountFile)) {
    Write-Host '[4/4] Provisioning isolated HermesBox Windows account (accept UAC prompt for full SID isolation)...' -ForegroundColor Yellow
    try {
        $setupScript = Join-Path $bin 'setup-account.ps1'
        $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$setupScript`"") -Verb RunAs -Wait -PassThru
        if ($p.ExitCode -eq 0 -and (Test-Path -LiteralPath $accountFile)) {
            Write-Host '      Account Mode provisioned successfully!' -ForegroundColor Green
        } else {
            Write-Warning '      Account setup skipped or declined; Hermes Box will run in zero-admin Token Mode.'
        }
    } catch {
        Write-Warning '      UAC prompt declined; Hermes Box will run in zero-admin Token Mode (run setup-account.ps1 elevated anytime).'
    }
} else {
    Write-Host '[4/4] Sandbox account already configured.' -ForegroundColor Green
}

Write-Host ''
Write-Host 'Running Hermes Box Self-Test...' -ForegroundColor Cyan
& (Join-Path $bin 'hermes.ps1') selftest
Write-Host ''
Write-Host 'Setup complete! Launch anytime via:' -ForegroundColor Green
Write-Host '  - Desktop / Start Menu: "Hermes Box"'
Write-Host '  - Chrome Toolbar: Click the "H" Hermes Box icon'
Write-Host '  - Terminal: hermesbox'

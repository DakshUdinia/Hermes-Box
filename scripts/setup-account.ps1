#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Create (or remove) the dedicated local account used by Hermes Box account mode.

.DESCRIPTION
  Account mode gives real SID-level isolation: the browser runs as a separate,
  non-admin local user, so it cannot read or write your profile at all.

  This script must run elevated. It:
    * creates a local user named HermesBox with a random password
    * stores the password DPAPI-encrypted in %LOCALAPPDATA%\Hermes\account.dat
    * restricts that file to your own account

  Uses the LocalAccounts cmdlets (no net.exe), so it cannot hang on the legacy
  net command and works on Windows 11 Home.

.EXAMPLE
  .\setup-account.ps1

.EXAMPLE
  .\setup-account.ps1 -Remove
#>
param(
    [switch]$Remove,
    [string]$UserName = 'HermesBox'
)

$ErrorActionPreference = 'Stop'
$dir = if ($env:HERMESBOX_HOME) { $env:HERMESBOX_HOME } else { Join-Path $env:LOCALAPPDATA 'HermesBox' }
$file = Join-Path $dir 'account.dat'
$log = Join-Path $dir 'setup.log'
$userListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'

function Get-SecondaryFixedDrives {
    $sysDrive = if ($env:SystemDrive) { $env:SystemDrive.TrimEnd('\') } else { 'C:' }
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
        Where-Object { $_.DeviceID -and $_.DeviceID -ne $sysDrive } |
        ForEach-Object { "$($_.DeviceID)\" }
}

function Log([string]$msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg
    Write-Host $line
    try { Add-Content -LiteralPath $log -Value $line -Encoding UTF8 } catch { }
}

trap {
    Log "ERROR: $($_.Exception.Message)"
    Log "at: $($_.InvocationInfo.PositionMessage)"
    exit 1
}

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Set-Content -LiteralPath $log -Value "setup started $(Get-Date -Format o) user=$($env:USERNAME)" -Encoding UTF8

if ($Remove) {
    foreach ($drv in @(Get-SecondaryFixedDrives)) {
        icacls.exe $drv /remove:d $UserName /Q 2>$null | Out-Null
    }
    Remove-ItemProperty -Path $userListKey -Name $UserName -Force -ErrorAction SilentlyContinue
    try {
        Remove-LocalUser -Name $UserName -ErrorAction Stop
        Log "removed local account '$UserName'"
    }
    catch {
        Log "could not remove account (may not exist): $($_.Exception.Message)"
    }
    # Drop the sandbox account's leftover profile folder too.
    $profile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -like "*\$UserName" }
    if ($profile) {
        try {
            Remove-CimInstance -InputObject $profile -ErrorAction Stop
            Log "removed profile $($profile.LocalPath)"
        }
        catch {
            Log "could not remove profile $($profile.LocalPath): $($_.Exception.Message)"
        }
    }
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    Log "removed credentials"
    return
}

# Cryptographically random 28-char password guaranteed to satisfy Windows complexity policies
$lowers = 'abcdefghijkmnopqrstuvwxyz'
$uppers = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
$digits = '23456789'
$syms   = '!@#$%&*+-=?'
$allChars = ($lowers + $uppers + $digits + $syms).ToCharArray()
$rngBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($rngBytes)
$rng.Dispose()
$pwChars = @(
    $lowers[$rngBytes[0] % $lowers.Length],
    $uppers[$rngBytes[1] % $uppers.Length],
    $digits[$rngBytes[2] % $digits.Length],
    $syms[$rngBytes[3] % $syms.Length]
)
for ($i = 4; $i -lt 28; $i++) {
    $pwChars += $allChars[$rngBytes[$i] % $allChars.Length]
}
$password = -join $pwChars
$secure = ConvertTo-SecureString $password -AsPlainText -Force

$existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($existing) {
    Set-LocalUser -Name $UserName -Password $secure
    Log "account exists, password rotated"
}
else {
    New-LocalUser -Name $UserName `
        -Password $secure `
        -Description 'Hermes Box sandbox account' `
        -AccountNeverExpires `
        -PasswordNeverExpires `
        -UserMayNotChangePassword | Out-Null
    Log "account created"
}

# Standard user only. New local accounts are already in Users, but be explicit.
try {
    Add-LocalGroupMember -Group 'Users' -Member $UserName -ErrorAction Stop
}
catch {
    # Already a member is not an error worth failing on.
}

$account = Get-LocalUser -Name $UserName
$groups = (Get-LocalGroupMember -Group 'Users' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*$UserName" } | Measure-Object).Count
$isAdmin = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*$UserName" } | Measure-Object).Count
Log "account ready: enabled=$($account.Enabled) inUsers=$groups inAdmins=$isAdmin"

# Hide from the Windows 11 sign-in / lock screen while keeping local interactive
# logon enabled (CreateProcessWithLogonW uses LOGON32_LOGON_INTERACTIVE).
New-Item -Path $userListKey -Force | Out-Null
New-ItemProperty -Path $userListKey -Name $UserName -Value 0 -PropertyType DWord -Force | Out-Null
Log "hidden '$UserName' from Windows sign-in screen"

# Deny network and RDP logon (SIDs in secedit INF must be prefixed with *).
try {
    $sid = (New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $rightsFile = Join-Path $env:TEMP "hermesbox_rights_$PID.inf"
    $sdbFile = Join-Path $env:TEMP "hermesbox_sec_$PID.sdb"
    @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeDenyNetworkLogonRight = *$sid
SeDenyRemoteInteractiveLogonRight = *$sid
"@ | Set-Content -LiteralPath $rightsFile -Encoding Unicode
    secedit /configure /db $sdbFile /cfg $rightsFile /areas USER_RIGHTS /quiet | Out-Null
    Remove-Item -LiteralPath $rightsFile, $sdbFile -Force -ErrorAction SilentlyContinue
    Log "denied network/RDP logon for $UserName"
}
catch {
    Log "warning: could not set secedit rights: $($_.Exception.Message)"
}

# Block the sandbox account from reading or writing non-OS fixed drives (D:, E:, F:).
foreach ($drv in @(Get-SecondaryFixedDrives)) {
    icacls.exe $drv /deny "${UserName}:(OI)(CI)(F)" /Q 2>$null | Out-Null
    Log "locked secondary drive $drv against $UserName (exit $LASTEXITCODE)"
}

# Lock down C:\ProgramData\HermesBox so the sandbox account can NEVER modify shared extensions or engine binaries.
$sharedRoot = Join-Path $env:ProgramData 'HermesBox'
$sharedExt  = Join-Path $sharedRoot 'extensions'
$sharedBoxes = Join-Path $sharedRoot 'boxes'
New-Item -ItemType Directory -Force -Path $sharedRoot, $sharedExt, $sharedBoxes | Out-Null
$callerAccount = "$env:USERDOMAIN\$env:USERNAME"
icacls.exe $sharedRoot /inheritance:r /remove:g $UserName /grant '*S-1-5-18:(OI)(CI)(F)' /grant '*S-1-5-32-544:(OI)(CI)(F)' /grant "${callerAccount}:(OI)(CI)(F)" /grant '*S-1-5-32-545:(RX)' /Q 2>$null | Out-Null
icacls.exe $sharedExt /inheritance:r /remove:g $UserName /grant '*S-1-5-18:(OI)(CI)(F)' /grant '*S-1-5-32-544:(OI)(CI)(F)' /grant "${callerAccount}:(OI)(CI)(F)" /grant '*S-1-5-32-545:(OI)(CI)(RX)' /Q 2>$null | Out-Null
icacls.exe "$sharedExt\*" /reset /T /Q 2>$null | Out-Null
icacls.exe $sharedBoxes /inheritance:r /remove:g $UserName /grant '*S-1-5-18:(OI)(CI)(F)' /grant '*S-1-5-32-544:(OI)(CI)(F)' /grant "${callerAccount}:(OI)(CI)(F)" /grant '*S-1-5-32-545:(RX)' /Q 2>$null | Out-Null
Log "hardened ACLs on $sharedRoot (shared extensions locked read-only against $UserName)"

$encrypted = ConvertFrom-SecureString $secure
$payload = @{ user = $UserName; password = $encrypted } | ConvertTo-Json -Compress

# Start clean: a previous run may have left a locked-down file behind.
if (Test-Path -LiteralPath $file) {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $file) {
        takeown /f $file 2>$null | Out-Null
        icacls $file /reset 2>$null | Out-Null
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
}
Set-Content -LiteralPath $file -Value $payload -Encoding UTF8
# No custom ACL: the file inherits the profile ACL (you, SYSTEM, Administrators),
# and DPAPI already ties the ciphertext to your account.

Log "credentials written to $file"
Log "account mode ready"

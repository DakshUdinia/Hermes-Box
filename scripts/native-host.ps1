#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

try {
    $stdin = [Console]::OpenStandardInput()
    $lenBuf = New-Object byte[] 4
    $read = $stdin.Read($lenBuf, 0, 4)
    if ($read -lt 4) { exit 0 }
    $msgLen = [BitConverter]::ToInt32($lenBuf, 0)
    if ($msgLen -le 0 -or $msgLen -gt 1048576) { exit 0 }

    $msgBuf = New-Object byte[] $msgLen
    $offset = 0
    while ($offset -lt $msgLen) {
        $n = $stdin.Read($msgBuf, $offset, ($msgLen - $offset))
        if ($n -le 0) { break }
        $offset += $n
    }

    $jsonStr = [Text.Encoding]::UTF8.GetString($msgBuf, 0, $offset)
    $payload = $jsonStr | ConvertFrom-Json

    $urls = @()
    if ($payload.urls) {
        foreach ($u in $payload.urls) {
            if (-not $u) { continue }
            $raw = ([string]$u).Trim()
            if ($raw -eq 'chrome://newtab') {
                $urls += 'chrome://newtab'
                continue
            }
            $parsed = $null
            if ([Uri]::TryCreate($raw, [UriKind]::Absolute, [ref]$parsed) -and ($parsed.Scheme -in @('http', 'https'))) {
                # AbsoluteUri RFC-3986 percent-encodes quotes, whitespace, and control chars so argument injection is impossible.
                $safeUrl = ($parsed.AbsoluteUri -replace '"', '%22' -replace '\s', '%20' -replace ',', '%2C')
                if ($safeUrl -and ($safeUrl -notmatch '["\s\r\n]')) {
                    $urls += $safeUrl
                }
            }
        }
    }
    $ublock = if ($null -ne $payload.ublock) { [bool]$payload.ublock } else { $true }
    $vpn    = if ($null -ne $payload.vpn)    { [bool]$payload.vpn }    else { $true }

    $binDir = Split-Path -Parent $PSCommandPath
    $hermesScript = Join-Path $binDir 'hermes.ps1'
    $psHost = if (Get-Command pwsh -ErrorAction SilentlyContinue) { (Get-Command pwsh).Source } else { "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }

    if ($payload.mode -eq 'gui') {
        $guiArgs = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$hermesScript`"",
            'gui',
            '-HideConsole'
        )
        Start-Process -FilePath $psHost -ArgumentList ($guiArgs -join ' ') | Out-Null
    } else {
        $argList = @(
            '-NoProfile',
            '-WindowStyle', 'Hidden',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$hermesScript`"",
            'run'
        )
        if ($urls.Count -gt 0) {
            $argList += '-Url'
            $argList += "`"$($urls -join ',')`""
        }
        if (-not $ublock) {
            $argList += '-NoUblock'
        }
        if (-not $vpn) {
            $argList += '-NoVpn'
        }
        Start-Process -FilePath $psHost -ArgumentList ($argList -join ' ') -WindowStyle Hidden | Out-Null
    }

    $respJson = '{"ok":true}'
    $respBytes = [Text.Encoding]::UTF8.GetBytes($respJson)
    $respLen = [BitConverter]::GetBytes([int]$respBytes.Length)
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($respLen, 0, 4)
    $stdout.Write($respBytes, 0, $respBytes.Length)
    $stdout.Flush()
}
catch {
    $errJson = @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
    $errBytes = [Text.Encoding]::UTF8.GetBytes($errJson)
    $errLen = [BitConverter]::GetBytes([int]$errBytes.Length)
    $stdout = [Console]::OpenStandardOutput()
    $stdout.Write($errLen, 0, 4)
    $stdout.Write($errBytes, 0, $errBytes.Length)
    $stdout.Flush()
}

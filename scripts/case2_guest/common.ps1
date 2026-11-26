# Shared helpers for the Case 2 guest scripts (Windows PowerShell 5.1).
$ErrorActionPreference = 'Stop'
$Work = 'C:\case2'
New-Item -ItemType Directory -Force $Work | Out-Null

function Get-DataDrive {
    $vol = Get-Volume | Where-Object FileSystemLabel -eq 'CASE2DATA' | Select-Object -First 1
    if (-not $vol) { throw 'Data disc CASE2DATA not found' }
    return "$($vol.DriveLetter):"
}

function Start-Log([string]$Name) {
    $path = Join-Path $Work "$Name-$(Get-Date -Format yyyyMMdd-HHmmss).log"
    Start-Transcript -Path $path | Out-Null
    return $path
}

function Stop-Log {
    Stop-Transcript | Out-Null
    Write-Host ''
    Read-Host 'Done. Press Enter to close'
}

# Step 4: run the Bandizip 6.29 installer (interactive) and record what was installed.
. (Join-Path $PSScriptRoot 'common.ps1')
$log = Start-Log '03-install-bandizip'
try {
    $d = Get-DataDrive
    $setup = "$d\installers\BANDIZIP6-SETUP-6.29.exe"
    $sig = Get-AuthenticodeSignature $setup
    Write-Host "Installer signature: $($sig.Status) / $($sig.SignerCertificate.Subject)"
    Write-Host 'Starting the installer. Keep the default install folder; do not start Bandizip at the end.'
    $p = Start-Process $setup -Wait -PassThru
    Write-Host "Installer exit code: $($p.ExitCode)"

    $exe = @('C:\Program Files\Bandizip\Bandizip.exe', 'C:\Program Files (x86)\Bandizip\Bandizip.exe') |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $exe) { throw 'Bandizip.exe not found in Program Files' }
    $v = (Get-Item $exe).VersionInfo
    $info = @(
        "Bandizip path: $exe"
        "FileVersion: $($v.FileVersion)  ProductVersion: $($v.ProductVersion)"
        "SHA256: $((Get-FileHash $exe -Algorithm SHA256).Hash)"
        "Signature: $((Get-AuthenticodeSignature $exe).Status)"
    )
    $info | Add-Content (Join-Path $Work 'environment.txt')
    $info | ForEach-Object { Write-Host $_ }
    Write-Host "`nNext: shut down the VM and take the snapshot before creating any ZIP."
} catch {
    Write-Host "ERROR: $_"
} finally {
    Write-Host "Log: $log"
    Stop-Log
}

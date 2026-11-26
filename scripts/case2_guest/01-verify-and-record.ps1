# Step 1-2: verify the data disc and record the guest environment.
. (Join-Path $PSScriptRoot 'common.ps1')
$log = Start-Log '01-verify-and-record'
try {
    powercfg /h off
    Write-Host 'Hibernation disabled (hiberfil.sys removed).'

    $d = Get-DataDrive
    Write-Host "Data disc: $d"
    $bad = 0; $n = 0
    foreach ($line in Get-Content "$d\SHA256SUMS.txt") {
        $h, $p = $line -split '  ', 2
        $n++
        if ((Get-FileHash "$d\$p" -Algorithm SHA256).Hash -ne $h) { $bad++; Write-Host "MISMATCH $p" }
    }
    Write-Host "Checked $n files. Mismatches: $bad"

    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $lic = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey IS NOT NULL AND Name LIKE 'Windows%'" |
        Select-Object -First 1
    $envInfo = @(
        "Recorded: $(Get-Date -Format o)"
        "Edition: $($cv.ProductName) / $($cv.EditionID)"
        "Version: $($cv.ReleaseId)  Build: $($cv.CurrentBuild).$($cv.UBR)"
        "ACP: $([System.Text.Encoding]::Default.CodePage)  OEMCP: $([Console]::OutputEncoding.CodePage)"
        "System locale: $((Get-WinSystemLocale).Name)  UI culture: $((Get-UICulture).Name)"
        "Time zone: $((Get-TimeZone).Id)"
        "zipfldr.dll: $((Get-Item "$env:WINDIR\System32\zipfldr.dll").VersionInfo.FileVersion)"
        "explorer.exe: $((Get-Item "$env:WINDIR\explorer.exe").VersionInfo.FileVersion)"
        "Activation LicenseStatus: $(if ($lic) { $lic.LicenseStatus } else { 'none' }) (1 = licensed)"
        "Data disc mismatches: $bad of $n"
    )
    $envInfo | Set-Content (Join-Path $Work 'environment.txt')
    Write-Host ''
    $envInfo | ForEach-Object { Write-Host $_ }
    if ($cv.CurrentBuild -ne '19041') { Write-Host "`nWARNING: build is not 19041 (Version 2004). Stop and report." }
    if ($bad -ne 0) { Write-Host "`nWARNING: data disc checksum mismatch. Stop and report." }
} catch {
    Write-Host "ERROR: $_"
} finally {
    Write-Host "Log: $log"
    Stop-Log
}

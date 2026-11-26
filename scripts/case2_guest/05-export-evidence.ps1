# Step 6: copy the run folder and guest logs to the separate evidence disk (CASE2EVID).
. (Join-Path $PSScriptRoot 'common.ps1')
$log = Start-Log '05-export-evidence'
try {
    $vol = Get-Volume | Where-Object FileSystemLabel -eq 'CASE2EVID' | Select-Object -First 1
    if (-not $vol) {
        $disk = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' -and $_.Size -le 4GB } |
            Select-Object -First 1
        if (-not $disk) { throw 'No empty evidence disk (<= 4 GB, uninitialised) is attached' }
        Write-Host "Initialising disk $($disk.Number) ($([math]::Round($disk.Size / 1MB)) MB) as CASE2EVID..."
        Initialize-Disk -Number $disk.Number -PartitionStyle MBR
        $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
        $vol = Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel CASE2EVID -Confirm:$false
    }
    $root = "$($vol.DriveLetter):\"
    $run = (Get-Content (Join-Path $Work 'last-run.txt') -Raw).Trim()
    if (-not (Test-Path $run)) { throw "Run folder not found: $run" }
    $runId = Split-Path $run -Leaf
    $dest = Join-Path $root $runId
    if (Test-Path $dest) { throw "$dest already exists; not overwriting" }
    Copy-Item $run $dest -Recurse
    $logs = Join-Path $root 'guest-logs'
    New-Item -ItemType Directory -Force $logs | Out-Null
    Get-ChildItem $Work -File | Where-Object { $_.Extension -in '.log', '.txt' } |
        ForEach-Object { Copy-Item $_.FullName (Join-Path $logs $_.Name) -Force }

    $lines = @(); $bad = 0
    foreach ($f in Get-ChildItem $dest -Recurse -File) {
        $rel = $f.FullName.Substring($dest.Length + 1)
        $h1 = (Get-FileHash -LiteralPath (Join-Path $run $rel) -Algorithm SHA256).Hash
        $h2 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        if ($h1 -ne $h2) { $bad++; Write-Host "MISMATCH $rel" }
        $lines += "$h2  $runId\$rel"
    }
    $srcCount = @(Get-ChildItem $run -Recurse -File).Count
    foreach ($f in Get-ChildItem $logs -File) {
        $lines += "$((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash)  guest-logs\$($f.Name)"
    }
    [IO.File]::WriteAllLines((Join-Path $root 'SHA256SUMS.txt'), $lines, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Copied $srcCount run files to $dest ; mismatches: $bad"
    Write-Host 'Next: shut down the VM (Start -> Power -> Shut down) and tell the host operator.'
} catch {
    Write-Host "ERROR: $_"
} finally {
    Write-Host "Log: $log"
    Stop-Log
}

# Step 3: install Python 3.11.9 offline, copy the checkout, install wheels, run tests.
. (Join-Path $PSScriptRoot 'common.ps1')
$log = Start-Log '02-install-python-and-test'
try {
    $d = Get-DataDrive
    $py = 'C:\Program Files\Python311\python.exe'
    if (-not (Test-Path $py)) {
        Write-Host 'Installing Python 3.11.9 (all users, add to PATH, no tests/docs)...'
        $p = Start-Process "$d\installers\python-3.11.9-amd64.exe" -Wait -PassThru -ArgumentList @(
            '/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_test=0', 'Include_doc=0',
            'Include_launcher=1', 'Shortcuts=0')
        Write-Host "Python installer exit code: $($p.ExitCode)"
    }
    & $py --version

    $repo = Join-Path $Work 'zip-fingerprinting'
    if (-not (Test-Path $repo)) {
        Write-Host "Copying checkout to $repo ..."
        Copy-Item "$d\checkout\zip-fingerprinting" $repo -Recurse
        # Files copied from a CD are read-only; the experiment writes inside the checkout.
        Get-ChildItem $repo -Recurse -File | ForEach-Object { $_.IsReadOnly = $false }
    }
    Set-Location $repo

    Write-Host 'Installing wheels offline...'
    & $py -m pip install --no-index --find-links "$d\wheels" -e . pytest Pillow tzdata
    Write-Host "pip exit code: $LASTEXITCODE"

    Write-Host 'Running test suite...'
    & $py -m pytest -q -p no:cacheprovider
    Write-Host "pytest exit code: $LASTEXITCODE"
} catch {
    Write-Host "ERROR: $_"
} finally {
    Write-Host "Log: $log"
    Stop-Log
}

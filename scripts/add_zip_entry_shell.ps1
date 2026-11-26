param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Source
)

# Used only on the screening's fresh working copy. CopyHere adds one file through the
# Windows compressed-folder handler (zipfldr), without Explorer UI or confirmations.
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject Shell.Application
$zipFolder = $null
$item = $null
try {
    $archivePath = (Resolve-Path -LiteralPath $Archive).Path
    $sourcePath = (Resolve-Path -LiteralPath $Source).Path
    $name = Split-Path -Leaf $sourcePath
    $zipFolder = $shell.NameSpace($archivePath)
    if ($null -eq $zipFolder) { throw 'Windows compressed-folder handler is unavailable.' }
    $existing = $zipFolder.ParseName($name)
    if ($null -ne $existing) { throw "ZIP entry already exists: $name" }
    # SILENT | NOCONFIRMATION | NOCONFIRMMKDIR | NOERRORUI
    $zipFolder.CopyHere($sourcePath, 1556)
    # CopyHere returns before zipfldr finishes; wait for the entry, a stable size and
    # an archive no other handle holds open.
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $lastSize = -1
    $stable = 0
    do {
        Start-Sleep -Milliseconds 200
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Shell addition timed out.' }
        $item = $zipFolder.ParseName($name)
        if ($null -eq $item) { continue }
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($item)
        $item = $null
        $size = (Get-Item -LiteralPath $archivePath).Length
        if ($size -eq $lastSize) { $stable++ } else { $stable = 0; $lastSize = $size }
        if ($stable -lt 3) { continue }
        try {
            $stream = [IO.File]::Open($archivePath, 'Open', 'Read', 'None')
            $stream.Close()
            break
        } catch [IO.IOException] {
            $stable = 0
        }
    } while ($true)
} finally {
    foreach ($comObject in @($item, $zipFolder, $shell)) {
        if ($null -ne $comObject) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($comObject)
        }
    }
}

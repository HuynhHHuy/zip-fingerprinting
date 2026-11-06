param(
    [Parameter(Mandatory = $true)][string]$Archive,
    [Parameter(Mandatory = $true)][string]$Destination,
    [Parameter(Mandatory = $true)][string]$Entry
)

# Used only on the simulator's fresh working copy. Move-out removes one entry
# through the Windows compressed-folder handler, without a Delete confirmation UI.
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject Shell.Application
$zipFolder = $null
$destinationFolder = $null
$item = $null
try {
    $zipFolder = $shell.NameSpace((Resolve-Path -LiteralPath $Archive).Path)
    $destinationFolder = $shell.NameSpace((Resolve-Path -LiteralPath $Destination).Path)
    if ($null -eq $zipFolder -or $null -eq $destinationFolder) {
        throw 'Windows compressed-folder handler is unavailable.'
    }
    $item = $zipFolder.ParseName($Entry)
    if ($null -eq $item) { throw "ZIP entry not found: $Entry" }
    # SILENT | NOCONFIRMATION | NOCONFIRMMKDIR | NOERRORUI
    $destinationFolder.MoveHere($item, 1556)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 100
        $remaining = $zipFolder.ParseName($Entry)
        if ($null -eq $remaining -and
            (Test-Path -LiteralPath (Join-Path $Destination $Entry))) { break }
        if ($null -ne $remaining) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($remaining)
        }
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Shell removal timed out.' }
    } while ($true)
} finally {
    foreach ($comObject in @($item, $destinationFolder, $zipFolder, $shell)) {
        if ($null -ne $comObject) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($comObject)
        }
    }
}

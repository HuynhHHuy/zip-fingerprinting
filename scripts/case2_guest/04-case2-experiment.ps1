# Step 5: Bandizip GUI creation -> seal -> Explorer Delete -> finalize (PH4-PROV-002 / #19).
# The operator does every GUI action by hand; this script only records what the UI shows
# (UI Automation tree, Explorer selection, timestamps) and writes the JSON logs the
# workflow expects. It never clicks, types into or edits an archive.
. (Join-Path $PSScriptRoot 'common.ps1')
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$log = Start-Log '04-case2-experiment'
$Utf8 = New-Object System.Text.UTF8Encoding $false
$Shell = New-Object -ComObject Shell.Application
$UIA = [System.Windows.Automation.AutomationElement]

function Now-Utc { (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'") }
function Wait-Operator([string]$Text) { Write-Host ''; Read-Host ">> $Text  [Enter]" | Out-Null }
function Save-Json([string]$Path, $Object) {
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 60), $Utf8)
}
function Copy-Dict($Source) {
    $d = [ordered]@{}; foreach ($k in $Source.Keys) { $d[$k] = $Source[$k] }; return $d
}
function Get-ItemNames($Items) {
    # Item.Name hides extensions when Explorer does; the path keeps the real file name.
    return , @($Items | ForEach-Object { [IO.Path]::GetFileName($_.Path) })
}
function Sort-Ordinal([string[]]$Names) {
    $a = [string[]]@($Names); [Array]::Sort($a, [StringComparer]::Ordinal); return , $a
}

$script:Budget = 0
function Get-UiaNode($El, [int]$Depth) {
    $script:Budget--
    $c = $El.Current
    $node = [ordered]@{
        control_type = $c.ControlType.ProgrammaticName -replace '^ControlType\.', ''
        name = $c.Name; automation_id = $c.AutomationId; class_name = $c.ClassName
        enabled = $c.IsEnabled
    }
    $p = $null
    if ($El.TryGetCurrentPattern([System.Windows.Automation.TogglePattern]::Pattern, [ref]$p)) {
        $node.toggle_state = [string]$p.Current.ToggleState }
    if ($El.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$p)) {
        $node.selected = $p.Current.IsSelected }
    if ($El.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$p)) {
        $node.value = $p.Current.Value }
    if ($Depth -lt 14 -and $script:Budget -gt 0) {
        $kids = @()
        $w = [System.Windows.Automation.TreeWalker]::ControlViewWalker
        $ch = $w.GetFirstChild($El)
        while ($ch -and $script:Budget -gt 0) {
            try { $kids += , (Get-UiaNode $ch ($Depth + 1)) } catch { }
            $ch = $w.GetNextSibling($ch)
        }
        if ($kids.Count) { $node.children = $kids }
    }
    return $node
}

function Get-ProcessWindows([string[]]$ProcessNames) {
    $result = @()
    foreach ($proc in Get-Process -Name $ProcessNames -ErrorAction SilentlyContinue) {
        $cond = New-Object System.Windows.Automation.PropertyCondition(
            $UIA::ProcessIdProperty, $proc.Id)
        foreach ($w in $UIA::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $cond)) {
            $result += , $w
        }
    }
    return , $result
}

function Get-Trees($Elements) {
    $trees = @()
    foreach ($e in $Elements) { $script:Budget = 4000; $trees += , (Get-UiaNode $e 0) }
    return , $trees
}

function Find-ExplorerWindow([string]$Path) {
    foreach ($w in $Shell.Windows()) {
        try { if ($w.Document.Folder.Self.Path -ieq $Path) { return $w } } catch { }
    }
    return $null
}

function Test-Closed([string]$Path) {
    for ($i = 0; $i -lt 20; $i++) {
        try { $f = [IO.File]::Open($Path, 'Open', 'Read', 'None'); $f.Close(); return $true }
        catch { Start-Sleep -Milliseconds 500 }
    }
    return $false
}

function Write-Observation([string]$Run, [string]$Name, $Data) {
    $path = Join-Path $Run $Name
    Save-Json $path $Data
    return [ordered]@{ path = $Name; sha256 = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower() }
}

function Invoke-Workflow([string[]]$Arguments) {
    $out = & $py -m experiments.explorer_delete @Arguments
    $code = $LASTEXITCODE
    $out | ForEach-Object { Write-Host "  $_" }
    Write-Host "  exit code: $code"
    $last = @($out | Where-Object { $_ -like '{*' }) | Select-Object -Last 1
    if (-not $last) { throw "Workflow printed no JSON (exit $code)" }
    return ($last | ConvertFrom-Json)
}

function Export-BandizipSettings([string]$Run, [string]$Name) {
    $target = Join-Path $Run $Name
    & reg.exe export 'HKCU\Software\Bandizip' $target /y | Out-Null
    if (Test-Path $target) { Write-Host "  Bandizip settings exported: $Name" }
    else { Write-Host '  (no HKCU\Software\Bandizip key to export)' }
}

try {
    $py = 'C:\Program Files\Python311\python.exe'
    $d = Get-DataDrive; $bad = 0; $n = 0
    foreach ($line in Get-Content "$d\SHA256SUMS.txt") {
        $h, $p = $line -split '  ', 2; $n++
        if ((Get-FileHash "$d\$p" -Algorithm SHA256).Hash -ne $h) { $bad++; Write-Host "MISMATCH $p" }
    }
    Write-Host "Data disc $d checked $n files. Mismatches: $bad"
    if ($bad) { throw 'Data disc checksum mismatch' }
    $repo = Join-Path $Work 'zip-fingerprinting'
    Set-Location $repo
    $exe = @('C:\Program Files\Bandizip\Bandizip.exe', 'C:\Program Files (x86)\Bandizip\Bandizip.exe') |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $exe) { throw 'Bandizip.exe not found' }
    $exeName = Split-Path $exe -Leaf
    $bzProcs = @('Bandizip', 'Bandizip32', 'Bandizip64', 'bz', 'BandizipUpdate')

    # ---------------------------------------------------------------- prepare
    Write-Host "`n=== 1/4 prepare (GUI creation, unicode-path) ==="
    $r = Invoke-Workflow @('prepare', '--creation-mode', 'gui', '--configuration', 'unicode-path', '--bandizip', $exe)
    if ($r.status -ne 'awaiting_creation') { throw "prepare ended with status $($r.status)" }
    $run = $r.run
    $meta = Get-Content (Join-Path $run 'metadata.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $runId = $meta.run_id
    $source = Join-Path $run 'source'
    $before = Join-Path $run 'before.zip'
    $after = Join-Path $run 'after.zip'
    $expected = Sort-Ordinal @($meta.source_manifest.PSObject.Properties.Name)
    Write-Host "Run: $run"

    # ------------------------------------------------------- settings snapshot
    Write-Host "`n=== 2/4 Bandizip settings ==="
    Write-Host 'Open Bandizip (Start menu) -> Options/Settings -> Compression. Set:'
    Write-Host '   * UTF-8 filename (or code page UTF-8)          : OFF'
    Write-Host '   * Unicode filename in extra header (0x7075)    : ON'
    Write-Host '   * Store NTFS time                              : ON'
    Write-Host '   If an option does not exist in 6.29, leave it and say so in the report.'
    Write-Host 'Leave the Settings window OPEN on the Compression page.'
    Wait-Operator 'Press Enter to record the settings window'
    $obs = [ordered]@{ observed_utc = Now-Utc; purpose = 'Bandizip compression settings before creation'
        windows = (Get-Trees (Get-ProcessWindows $bzProcs)) }
    Save-Json (Join-Path $run 'creation-settings.json') $obs
    Export-BandizipSettings $run 'bandizip-settings-before.reg'
    Write-Host '  Recorded creation-settings.json. Now click OK and CLOSE Bandizip completely.'

    # --------------------------------------------------------------- creation
    Write-Host "`n=== 3/4 GUI creation ==="
    Wait-Operator 'Bandizip closed? Press Enter to START the creation phase'
    $started = Now-Utc
    Start-Process explorer.exe -ArgumentList "`"$source`""
    Write-Host 'An Explorer window opens on the source folder. In it:'
    Write-Host '   a) Select ALL FOUR files (Ctrl+A).'
    Write-Host '   b) Right-click -> Bandizip "Add to archive..." (the dialog with options).'
    Write-Host '   c) Format ZIP, level Normal. Set the archive path to exactly:'
    Write-Host "        $before"
    Write-Host '   d) Do NOT press Start yet; keep the four files selected in Explorer.'
    while ($true) {
        Wait-Operator 'Dialog ready (not started)? Press Enter to record BEFORE'
        $win = Find-ExplorerWindow $source
        $sel = @(); if ($win) { $sel = Get-ItemNames $win.Document.SelectedItems() }
        $sel = Sort-Ordinal $sel
        Write-Host "  Explorer selection: $($sel -join ' | ')"
        if (($sel -join '|') -ceq ($expected -join '|')) { break }
        Write-Host '  Selection is not exactly the four source files. Fix it and try again.'
    }
    $bzWindows = Get-ProcessWindows $bzProcs
    $title = (@($bzWindows | ForEach-Object { $_.Current.Name } | Where-Object { $_ }) -join ' | ')
    if (-not $title) { $title = $win.LocationName }
    $common = [ordered]@{ run_id = $runId; archive = $before; application = $exeName
        source_directory = $source; executable = $meta.tool.executable }
    $o1 = (Copy-Dict $common)
    $o1.phase = 'before'; $o1.observed_utc = Now-Utc; $o1.window_title = $title
    $o1.selected_entries = $sel
    $o1.accessibility_tree = [ordered]@{
        archiver_windows = (Get-Trees $bzWindows)
        explorer_window = (Get-Trees @($UIA::FromHandle([IntPtr]$win.HWND))) }
    $rec1 = Write-Observation $run 'creation-before.json' $o1
    Write-Host '  Recorded creation-before.json'
    Write-Host 'Now press Start/OK in the Bandizip dialog. When it has finished, close every'
    Write-Host 'Bandizip window (do not open the new ZIP), keep the Explorer window open.'
    while ($true) {
        Wait-Operator 'Compression finished and Bandizip closed? Press Enter to record AFTER'
        if (Test-Path $before) { break }
        Write-Host "  $before does not exist yet. Check the archive path."
    }
    $o2 = (Copy-Dict $common)
    $o2.phase = 'after'; $o2.observed_utc = Now-Utc
    $bzWindows = Get-ProcessWindows $bzProcs
    $explorerTree = Get-Trees @($UIA::FromHandle([IntPtr]$win.HWND))
    $o2.window_title = $win.LocationName
    $o2.accessibility_tree = [ordered]@{ archiver_windows = (Get-Trees $bzWindows); explorer_window = $explorerTree }
    $o2.archive_size = (Get-Item $before).Length
    $rec2 = Write-Observation $run 'creation-after.json' $o2
    $closed = Test-Closed $before
    $ended = Now-Utc
    Export-BandizipSettings $run 'bandizip-settings-after.reg'
    $clog = (Copy-Dict $common)
    $clog.action = 'Create'; $clog.selected_entries = $expected
    $clog.started_utc = $started; $clog.ended_utc = $ended; $clog.archive_closed = $closed
    $clog.evidence_level = 'ui_observed'; $clog.observations = @($rec1, $rec2)
    $clog.operator_note = 'GUI actions by the operator; recorded by scripts\04-case2-experiment.ps1'
    Save-Json (Join-Path $run 'creation-log.json') $clog
    if (-not $closed) { throw 'before.zip is still open by another process; close Bandizip' }
    $r = Invoke-Workflow @('seal-creation', $run, '--gui-log', (Join-Path $run 'creation-log.json'))
    if ($r.status -ne 'awaiting_gui') { throw "seal-creation ended with status $($r.status)" }

    # ----------------------------------------------------------------- delete
    Write-Host "`n=== 4/4 Explorer Delete ==="
    Write-Host 'Close the source Explorer window now.'
    Write-Host "Association of .zip: $(& cmd.exe /c 'assoc .zip 2>nul')"
    $meta = Get-Content (Join-Path $run 'metadata.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    while ($true) {
        Wait-Operator 'Press Enter to START the delete phase (opens after.zip in Explorer)'
        $started = Now-Utc
        Start-Process explorer.exe -ArgumentList "`"$after`""
        $zw = $null
        for ($i = 0; $i -lt 20 -and -not $zw; $i++) { Start-Sleep -Milliseconds 500; $zw = Find-ExplorerWindow $after }
        if ($zw) { break }
        Write-Host '  Explorer did not open after.zip as a compressed folder (Bandizip may have'
        Write-Host '  opened it instead). Close Bandizip without changing anything, then in Bandizip'
        Write-Host '  Settings -> Association untick ZIP, Apply, OK, close Bandizip, and retry.'
    }
    Write-Host 'In the after.zip window click ONLY target.txt (single selection).'
    while ($true) {
        Wait-Operator 'target.txt selected? Press Enter to record BEFORE'
        $sel = @(Get-ItemNames $zw.Document.SelectedItems())
        Write-Host "  Selection: $($sel -join ' | ')"
        if ($sel.Count -eq 1 -and $sel[0] -ceq 'target.txt') { break }
        Write-Host '  Select exactly target.txt and try again.'
    }
    $common = [ordered]@{ run_id = $runId; archive = $after; application = 'explorer.exe' }
    $d1 = (Copy-Dict $common)
    $d1.phase = 'before'; $d1.observed_utc = Now-Utc; $d1.window_title = $zw.LocationName
    $d1.selected_target = 'target.txt'
    $d1.items = (Get-ItemNames $zw.Document.Folder.Items())
    $d1.accessibility_tree = (Get-Trees @($UIA::FromHandle([IntPtr]$zw.HWND)))
    $rec1 = Write-Observation $run 'delete-before.json' $d1
    Write-Host '  Recorded delete-before.json'
    Write-Host 'Now press the Delete key, confirm with Yes, and wait until target.txt is gone.'
    Wait-Operator 'Deleted and list refreshed? Press Enter to record AFTER'
    $d2 = (Copy-Dict $common)
    $d2.phase = 'after'; $d2.observed_utc = Now-Utc; $d2.window_title = $zw.LocationName
    $d2.items = (Get-ItemNames $zw.Document.Folder.Items())
    $d2.accessibility_tree = (Get-Trees @($UIA::FromHandle([IntPtr]$zw.HWND)))
    $rec2 = Write-Observation $run 'delete-after.json' $d2
    Write-Host "  Items now: $($d2.items -join ' | ')"
    $zw.Quit()
    $closed = Test-Closed $after
    $ended = Now-Utc
    $dlog = (Copy-Dict $common)
    $dlog.target = 'target.txt'; $dlog.action = 'Delete'
    $dlog.started_utc = $started; $dlog.ended_utc = $ended; $dlog.archive_closed = $closed
    $dlog.evidence_level = 'ui_observed'; $dlog.observations = @($rec1, $rec2)
    $dlog.operator_note = 'GUI actions by the operator; recorded by scripts\04-case2-experiment.ps1'
    Save-Json (Join-Path $run 'delete-log.json') $dlog
    if (-not $closed) { throw 'after.zip is still open; close Explorer windows and rerun finalize by hand' }
    $r = Invoke-Workflow @('finalize', $run, '--gui-log', (Join-Path $run 'delete-log.json'), '--require-case2')
    Write-Host "`nRESULT  status=$($r.status)  native_case2=$($r.native_case2)"
    Get-Content (Join-Path $run 'report.md') -Encoding UTF8 | ForEach-Object { Write-Host "  $_" }
    Set-Content (Join-Path $Work 'last-run.txt') $run
} catch {
    Write-Host "ERROR: $_"
    if ($run) { Set-Content (Join-Path $Work 'last-run.txt') $run; Write-Host "Run kept: $run" }
} finally {
    Write-Host "Log: $log"
    Stop-Log
}

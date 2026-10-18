param([Parameter(Mandatory = $true)][string]$Application)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$preview = Start-Process -FilePath $Application -PassThru -WindowStyle Hidden
$checkLabel = 'Check'
$confirmLabel = 'Confirm'
$backLabel = 'Cancel'

function Assert-Running {
    $preview.Refresh()
    if ($preview.HasExited) { throw "GUI exited unexpectedly: $($preview.ExitCode)" }
}

function Find-Button([string]$Name) {
    Assert-Running
    $window = [System.Windows.Automation.AutomationElement]::FromHandle($preview.MainWindowHandle)
    $condition = [System.Windows.Automation.AndCondition]::new(
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Button),
        [System.Windows.Automation.PropertyCondition]::new(
            [System.Windows.Automation.AutomationElement]::NameProperty, $Name))
    return $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
}

function Click-Button([string]$Name) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $button = Find-Button $Name
        if ($null -ne $button -and $button.Current.IsEnabled) {
            $button.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
            Start-Sleep -Milliseconds 200
            Assert-Running
            return
        }
        Start-Sleep -Milliseconds 50
    } while ($timer.Elapsed.TotalSeconds -lt 8)
    throw "Enabled button not found: $Name"
}

try {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        Assert-Running
        if ($preview.MainWindowHandle -ne 0) { break }
        Start-Sleep -Milliseconds 50
    } while ($timer.Elapsed.TotalSeconds -lt 8)
    if ($preview.MainWindowHandle -eq 0) { throw 'GUI window missing' }
    # Leave enough event-loop turns between joins to exercise the pthread cache.
    for ($index = 0; $index -lt 5; $index++) { Click-Button $checkLabel }
    for ($index = 0; $index -lt 2; $index++) {
        Click-Button 'Install Widevine'
        if ($null -eq (Find-Button $confirmLabel)) { throw 'Install confirmation missing' }
        Click-Button $backLabel
    }
    Click-Button 'Settings'
    Click-Button 'Help'
    Click-Button 'Back'
    Click-Button 'About'
    Click-Button 'Back'
    Click-Button 'Back'
    Click-Button 'Restore'
    # The surrounding Python fixture has no managed backup. This must show an
    # error, keep the window usable and leave every fixture file unchanged.
    Click-Button $confirmLabel
    Click-Button $checkLabel
    [void]$preview.CloseMainWindow()
    if (-not $preview.WaitForExit(5000)) { throw 'GUI did not close cleanly' }
    if ($preview.ExitCode -ne 0) { throw "GUI exit code: $($preview.ExitCode)" }
    Write-Output 'Real GUI button interactions and failed-restore recovery passed'
}
finally {
    if (-not $preview.HasExited) { [void]$preview.CloseMainWindow() }
}

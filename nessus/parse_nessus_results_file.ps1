<# .nessus XML Parser
For those times when you want a quick and dirty listing of what vulnerabilities
are on a given system, but either can't import to SecurityCenter, or just want
a stupidly quick'n'dirty listing of vulnerabilities which are affecting a given
host.
#>


Function Get-FileName($initialDirectory) {
    <#
    Retrieve a file name from a GUI-based file picker

    Parameters:
        $initialDirectory: The file path to set the file picker to initially
    
    Returns:
        The full path to the selected file
    #>  # Yes, it's a Pythonic comment... hiss!
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "Nessus Results File (*.nessus)| *.nessus"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}


Function Get-Severity($sev_int) {
    <#
    Convert the Nessus integer severity to the corresponding human-readable severity.

    Parameters:
        $sev_int: The Nessus severity integer. Permissible values are 0,1,2,3,4, corresponding
                  to Informational, Low, Medium, High, and Critical, respectively.
    
    Returns:
        A string corresponding to the passed-in severity integer value. If no value matches
        (which shouldn't happen), integer -1 is returned.
    #>
    if ($sev_int -eq 0) { return "Info" }
    elseif ($sev_int -eq 1) { return "Low" }
    elseif ($sev_int -eq 2) { return "Medium" }
    elseif ($sev_int -eq 3) { return "High" }
    elseif ($sev_int -eq 4) { return "Critical" }
    else { return -1 }
}


[xml]$nessusFile = Get-Content(Get-FileName(Get-Location))

Write-Host "The Policy used was:" $nessusFile.NessusClientData_v2.Policy.policyName


foreach ($nessus_host in $nessusFile.NessusClientData_v2.Report.ReportHost) {
    Write-Host -ForegroundColor Yellow "-----------Host:" $nessus_host.name "-----------"

    <# Get each vulnerability from the host, then sort the resultant list by severity and plugin name #>
    foreach ($item in ($nessus_host.ReportItem | Sort-Object -Property @{Expression = "severity"; Descending = $true}, @{Expression = "plugin_name"; Descending = $false})) {
        if ($item.severity -ne 0) {  <# Ignore informationals #>
            Write-Host (Get-Severity($item.severity)) "--" $item.plugin_name
        }
    }
    Write-Host ""
}

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


# Create a stream reader (PoSH /will/ choke if using Get-Content on files of any real size)
$stream_reader = New-Object IO.StreamReader(Get-FileName(Get-Location))
# Then get the XML reader
$xml_reader = [Xml.XmlReader]::Create($stream_reader)
# Skip to the first content node
$xml_reader.MoveToContent()


# Make a storage location for storing the information we are looking for as we process the file.
$storage = @()
# Nessus stores scan results in <ReportHost> nodes; go to the first one.
while($xml_reader.ReadToFollowing("ReportHost")) {
    # Get the ReportHost XML node's contents (as XML) for simpler processing (and so we are not constrained by the forward-only reader)
    [xml]$report = $xml_reader.ReadOuterXml()
    
    Write-Host -ForegroundColor Cyan "/\/\/\/\/\ Begin Host :" $report.ReportHost.name ""

    foreach ($item in ($report.ReportHost.ReportItem | Sort-Object -Property @{Expression = "severity"; Descending = $true}, @{Expression = "plugin_name"; Descending = $false})) {
        if ($item.severity -ne 0) {  <# Ignore informationals #>
            Write-Host (Get-Severity($item.severity)) "--" $item.plugin_name
        }
    }

    # Example: Get the scan duration and IP address, and store
    $plugin_19506 = ($report.ReportHost.ReportItem | Where-Object {$_.pluginID -eq 19506})
    # Split the plugin output text on CRLF
    foreach ($line in $plugin_19506.plugin_output.Split("`r`n")) {
        if ($line -like "*Scan duration : *") {
            $duration = $line
            $storage += [pscustomobject]@{
                "ip_or_host" = $report.ReportHost.name;
                "duration" = $duration;
            }
        }
    }
    Write-Host -ForegroundColor Cyan "\/\/\/\/\/ End Host :" $report.ReportHost.name ""
    Write-Host ""
}

<#
Using a template .nessus file, generates a .nessus file which purges passed in IPs from a
SecurityCenter repository upon import. For implementation simplicity, the source IP
text file must only have a single IP per line.
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
    $OpenFileDialog.filter = @("Nessus Results File (*.nessus)| *.nessus|Text File with IPs (*.txt) | *.txt")
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}


# Get the XML data...
Write-Host -ForegroundColor Yellow "Give me the removeip.nessus template..."
[xml]$nessusFile = Get-Content(Get-FileName(Get-Location))
# Get the targets...
Write-Host -ForegroundColor Yellow "Give me text file with IPs to remove (one per line)..."
$target_ip_addrs = Get-Content(Get-FileName(Get-Location))

<### Change out the template IP for the new IP(s) (Lines 21, 4378, 4380) ###>
# Line 21: NessusClientData_v2.Policy.Preferences.ServerPreferences.preference; Get the 'TARGET' name/value pair
$xml_node = $nessusFile.NessusClientData_v2.Policy.Preferences.ServerPreferences.preference | Where-Object {$_.Name -eq "TARGET"}

<# Replace Line 21 with the target(s); Format is a comma separated list of either single IP, or range
   e.g., 1.2.3.4,2.3.4.0-2.3.4.255
#>
$concatenated_ips = ""
foreach ($line in $target_ip_addrs) {
    $concatenated_ips += $line + ","
}
$concatenated_ips = $concatenated_ips.TrimEnd(',')
$xml_node.value = $concatenated_ips

# Store the XML location/node of our template
$template_node = ($nessusFile.NessusClientData_v2.Report.ReportHost | Where-Object {$_.Name -eq "777.333.111.999"})
foreach ($target in $target_ip_addrs) {
    # Line 4378: $nessusFile.NessusClientData_v2.Report.ReportHost
    $editable_node = $template_node.Clone()  #This isn't linked to the $nessusFile XML object
    # Edit the IP (Line 4378)
    $editable_node.name = $target.ToString()
    # Line 4379-4381: $editable_node.HostProperties.tag || Three sub-items: HOST_END, host-ip, HOST_START
    $host_end = $editable_node.HostProperties.tag | Where-Object {$_.Name -eq "HOST_END"}
    $host_end.'#text' = (Get-Date -UFormat "%a %b %d %T %Y" (Get-Date).AddSeconds(10)).ToString()
    $host_ip = $editable_node.HostProperties.tag | Where-Object {$_.Name -eq "host-ip"}
    $host_ip.'#text' = $target.ToString()
    $host_start = $editable_node.HostProperties.tag | Where-Object {$_.Name -eq "HOST_START"}
    $host_start.'#text' = (Get-Date -UFormat "%a %b %d %T %Y" (Get-Date).AddSeconds(-10)).ToString()

    # Add the new node to the XML tree
    [void]$template_node.ParentNode.AppendChild($editable_node)
}
# Remove the source templated node
[void]$template_node.ParentNode.RemoveChild($template_node)

# Write-out the new XML file
$output_filename = (Get-Location).ToString() + "\Remove IP Nessus File - Populated.nessus"
$nessusFile.Save($output_filename)

Write-Host -ForegroundColor Green "Complete!"
Start-Sleep -Seconds 2

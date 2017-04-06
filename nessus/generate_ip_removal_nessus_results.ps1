<#
Using a template .nessus file, generates a .nessus file which purges passed in IPs from a
SecurityCenter repository upon import. IP information must be in one of the following
formats:
- Raw IP: 1.2.3.4
- CIDR Range: 192.168.1.0/24
- IP To-From Range: 10.10.10.0-10.10.10.20

Requires WMF v5
#>

Function Get-FileName() {
    <#
    Retrieve a file name from a GUI-based file picker

    Parameters:
        $initialDirectory: The file path to set the file picker to initially
    
    Returns:
        The full path to the selected file
    #>  # Yes, it's a Pythonic comment... hiss!
    param(
        $initialDirectory,
        $filter
    )
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = @($filter)
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

function Get-IPRange {
<#
    Get IP addresses in a range

    Example usage:
    - Get-IPrange -start 192.168.8.2 -end 192.168.8.20
    - Get-IPrange -ip 192.168.8.3 -cidr 24
    Reference: https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b
#>
    param (
        [string]$start,
        [string]$end,
        [string]$ip,
        [string]$mask,
        [int]$cidr
    )
    function IP-toINT64 () {
        param ($ip)
        $octets = $ip.split(".")
        return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
    }
    function INT64-toIP() {
        param ([int64]$int)
        return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
    }
    if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)}
    if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) }
    if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)}
    if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)}
    if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))}
    if ($ip) {
        $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring
        $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring
    }
    else {
        $startaddr = IP-toINT64 -ip $start
        $endaddr = IP-toINT64 -ip $end
    }
    for ($i = $startaddr; $i -le $endaddr; $i++) {
        INT64-toIP -int $i
    }
}

# Get the XML data...
Write-Host -ForegroundColor Yellow "Give me the removeip.nessus template..."
[xml]$nessusFile = Get-Content(Get-FileName -initialDirectory (Get-Location) -filter "Nessus Results File (*.nessus)| *.nessus")
# Get the targets...
Write-Host -ForegroundColor Yellow "Give me text file with IPs to remove (one per line)..."
$target_ip_file = Get-FileName -initialDirectory (Get-Location) -filter "Text File with IPs (*.txt) | *.txt"
$target_ip_addrs = Get-Content($target_ip_file)

<### Change out the template IP for the new IP(s) (Lines 21, 4378, 4380) ###>
# Line 21: NessusClientData_v2.Policy.Preferences.ServerPreferences.preference; Get the 'TARGET' name/value pair
$xml_node = $nessusFile.NessusClientData_v2.Policy.Preferences.ServerPreferences.preference | Where-Object {$_.Name -eq "TARGET"}

<# Replace Line 21 with the target(s); Format is a comma separated list of either single IP, or range
   e.g., 1.2.3.4,2.3.4.0-2.3.4.255
#>
$concatenated_ips = ""
foreach ($line in $target_ip_addrs) {
    if ([System.Net.IPAddress]::TryParse($line, [ref]'0.0.0.0')) {
        # Is the line itself an IP?
        $concatenated_ips += $line + ","
    }
    elseif ($line.Contains('/')) {
        # Maybe it is a CIDR range!?
        $cidr_split = $line.Split('/')
        $result = Get-IPRange -ip $cidr_split[0] -cidr $cidr_split[1]
        foreach ($entry in $result) {
            $concatenated_ips += $entry + ","
        }
    }
    elseif ($line.Contains('-')) {
        # Or even a range?!
        $range_split = $line.Split('-')
        $result = Get-IPRange -start $range_split[0] -end $range_split[1]
        foreach ($entry in $result) {
            $concatenated_ips += $entry + ","
        }
    }
    else {
        # WHARRGARBL! No one here but us kittens. Skip this $line.
    }
}
$concatenated_ips = $concatenated_ips.TrimEnd(',')
$target_ip_addrs = $concatenated_ips.Split(',')
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
$nessus_output_filename = (Split-Path $target_ip_file) + "\Remove IP Nessus File - Populated.nessus"
$nessusFile.Save($nessus_output_filename)

# Compress the .nessus file, and remove the .nessus file
$zip_output_filename = (Split-Path $target_ip_file) + "\Remove IP Nessus File - Populated.zip"
Compress-Archive $nessus_output_filename -DestinationPath $zip_output_filename
Remove-Item $nessus_output_filename


Write-Host -ForegroundColor Green "Complete!"
Start-Sleep -Seconds 2

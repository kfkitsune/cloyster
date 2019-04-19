<#
    Automatically create a .nessus IP purge 'results' file, and import it
    into a specified SecurityCenter.
    
    The template for the removal process is at:
      https://github.com/kfkitsune/cloyster/blob/master/nessus/generate_ip_removal_nessus_results.removeip.nessus
    The IP list can be in the format of:
      - 10.20.30.40
      - 172.16.0.0/19
      - 192.168.0.0-192.168.0.10
#>

try {  ### Begin module import block ###
    $location_of_modules = ";$env:USERPROFILE\Documents\AuthScripts\modules"
    if ($env:PSModulePath -notlike ('*' + $location_of_modules + '*')) {
        $env:PSModulePath += $location_of_modules
    }
    # Load the modules
    Import-Module sc.api.core -ErrorAction Stop -DisableNameChecking
    Import-Module KFK-CommonFunctions -ErrorAction Stop -DisableNameChecking
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###

$uri = "";
$configFileName = '.\sc.conf'
$chosenCertThumb = "";
$scriptDebug = $false


function Read-ConfigFile {
    if (Test-Path .\sc.conf) {
        $conf = Get-Content .\sc.conf
        $script:uri = ($conf | ConvertFrom-Json).uri
    }
    else {
        while ($uri -eq "") {
            $input = Read-Host -Prompt "Provide the SecurityCenter URI, no trailing slash"
            if (($input -like "https://*") -and ($input -notlike "https://*/")) {
                $script:uri = $input
                @{ "uri" = $script:uri } | ConvertTo-Json | Out-File -FilePath $configFileName
            }
        }
    }
}


function Output-Debug { # Simple output if we are debugging.
    param($req)
    if ($scriptDebug) {
        $Global:DebugPreference = "Continue"
        Write-Debug $req
        $Global:DebugPreference = "SilentlyContinue"
    }
}

# --- Functions for the automated purge of IPs v/

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

Read-ConfigFile

$chosenCertThumb = Invoke-CertificateChooser

SC-Authenticate -pkiThumbprint $chosenCertThumb -uri $uri | Out-Null

# Get a listing of the repositories and prompt for which to use
$resp = SC-Get-Repositories -type Local -name
$repos = @()
foreach ($repo in $resp.response) {
    $repos += [int]$repo.id
    Write-Host "[" $repo.id "] - " $repo.name
}
[int]$repository_selected = Read-Host -Prompt "Enter the repository number to purge data from; other values exit."
if ($repository_selected -notin $repos) {
    Write-Host -ForegroundColor Red "Invalid option selected; terminating execution..."
    exit
}

# Then process the IP purge request...
# Get the XML data...
Write-Host -ForegroundColor Yellow "Give me the removeip.nessus template..."
$path = Get-FileName -initialDirectory (Get-Location) -filter "Nessus Results File (*.nessus)| *.nessus"
[xml]$nessusFile = Get-Content($path) -ErrorAction Stop
# Get the targets...
Write-Host -ForegroundColor Yellow "Give me text file with IPs to remove (one per line)..."
$path = Get-FileName -initialDirectory (Get-Location) -filter "Text File with IPs (*.txt) | *.txt"
$target_ip_file_content = Get-Content($path) -ErrorAction Stop

# Sanity check:
if (($nessusFile -eq $null) -or ($target_ip_file_content -eq $null)) { throw "Something happened..." }

<### Change out the template IP for the new IP(s) (Lines 21, 4378, 4380) ###>
# Line 21: NessusClientData_v2.Policy.Preferences.ServerPreferences.preference; Get the 'TARGET' name/value pair
$xml_node = $nessusFile.NessusClientData_v2.Policy.Preferences.ServerPreferences.preference | Where-Object {$_.Name -eq "TARGET"}

<# Replace Line 21 with the target(s); Format is a comma separated list of either single IP, or range
   e.g., 1.2.3.4,2.3.4.0-2.3.4.255
#>
$progress = 0
$target_ip_addrs = @()
foreach ($line in $target_ip_file_content) {
    Write-Progress -Activity "Reading in IP lines" -CurrentOperation $line -PercentComplete (100 * ($progress / $target_ip_file_content.Count ))
    if ([System.Net.IPAddress]::TryParse($line, [ref]'0.0.0.0')) {
        # Is the line itself an IP?
        $target_ip_addrs += $line
    }
    elseif ($line.Contains('/')) {
        # Maybe it is a CIDR range!?
        $cidr_split = $line.Split('/')
        $target_ip_addrs += Get-IPRange -ip $cidr_split[0] -cidr $cidr_split[1]
    }
    elseif ($line.Contains('-')) {
        # Or even a range?!
        $range_split = $line.Split('-')
        $target_ip_addrs += Get-IPRange -start $range_split[0] -end $range_split[1]
    }
    # No match? Then... WHARRGARBL! No one here but us kittens. Skip this $line.

    $progress++
}
# Concatenation out here is more along the lines of O(1), instead of O(n) above.
$concatenated_ips = [String]::Join(',', $target_ip_addrs)

# We need IP addresses to continue, otherwise the SC backend will error out due to the malformed file.
if ($concatenated_ips -eq "") {
    throw "No IP addresses found in the input file. Terminating execution."
}

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
$nessus_output_filename = (Split-Path $path) + "\Remove IP Nessus File - Populated.nessus"
$nessusFile.Save($nessus_output_filename)

# Compress the .nessus file, and remove the .nessus file
$zip_output_filename = (Split-Path $path) + "\Remove IP Nessus File - Populated.zip"
Compress-Archive $nessus_output_filename -DestinationPath $zip_output_filename -Force
Remove-Item $nessus_output_filename

# Now that we have the zipped .nessus file, upload it...
$sc_uploaded_filename = SC-Upload-File -filePath $zip_output_filename

# Then issue the command to import it.
$resp = SC-Import-NessusResults -generatedFilename $sc_uploaded_filename -repositoryID $repository_selected

# Did the upload complete successfully?
if ($resp.error_code -eq 0) {
    Remove-Item $zip_output_filename
    Write-Host -ForegroundColor Green "Upload and import successful!"
}
else {
    # OwO -- Something Happened(TM). (Seriously, how is that a useful error, Microsoft?)
    Write-Host -ForegroundColor Red "Upload/Import Unsuccessful..."
}

# Cleanly close out of the session
SC-Logout | Out-Null

Start-Sleep -Seconds 3

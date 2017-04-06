<#
    Automatically create a .nessus IP purge 'results' file, and import it
    into a specified SecurityCenter.
    
    The template for the removal process is at:
      https://github.com/kfkitsune/cloyster/blob/master/nessus/generate_ip_removal_nessus_results.removeip.nessus
    The IP list can be in the format of:
      - 10.20.30.40
      - 172.16.0.0
      - 192.168.0.0-192.168.0.10
#>

try {  ### Begin module import block ###
    Import-Module $env:USERPROFILE\Documents\AuthScripts\Modules\KFK-CommonFunctions.psm1 -ErrorAction Stop -DisableNameChecking
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###

$scURI = "";  # Optional; Use if not using external cred/conf file.
$chosenCertThumb = "";
$scToken = "";
$scSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession;
$scUsername = "";  # Optional; Use if not using external cred/conf file.
$scPassword = "";  # Optional; Use if not using external cred/conf file.
$scResponse = "";
$scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList "foo", (ConvertTo-SecureString "foo" -AsPlainText -Force)
$scCredentialsFileName = ".\scCredentials.conf"
$scCredentialsKey = @();  # If changed, scCredentials.conf is invalid and must be regenerated. Can be read from conf file. 24 bytes.
$scCredentialsKeyFileName = ".\pluginIAVMMapping.conf"
$scUseExternalCredentials = $true
$scPKIAuthOnly = $true
$externalConfig = $true
$scriptDebug = $false


function Read-ConfigFile {
    [byte[]]$tmp = @()  # Storage for the key
    if ($externalConfig -and (Test-Path -Path $scCredentialsKeyFileName)) {
        $config = (Get-Content -Path $scCredentialsKeyFileName) -join "`n" | ConvertFrom-Json
        foreach ($i in $config.key.GetEnumerator()) {
            $tmp += [byte]$i
        }
        $script:scCredentialsKey = $tmp
    }
    else {  # Generate the key, since it doesn't exist...
        # $tmp = New-Object System.Collections.ArrayList
        for ($i=0; $i -lt 24; $i++) {
            $rand = Get-Random -Minimum 0 -Maximum 255
            # $tmp.Add($rand) | Out-Null
            $tmp += [byte]$rand
        }
        $Local:zz = @{}
        $Local:zz.Add("key", $tmp)
        $Local:zz | ConvertTo-Json | Out-File -FilePath $scCredentialsKeyFileName
        if (Test-Path -Path $scCredentialsFileName) {  # Remove the credentials (if they exist), since we had to generate the key (they're invalid)
            Remove-Item -Path $scCredentialsFileName
        }
        $script:scCredentialsKey = $tmp
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


function SC-GetCredentials {
    # Do we even care about the external credentials? If not, use what's in the script.
    if (!$scUseExternalCredentials) {
        # Only attempt authentication via PKI?
        if (!$scPKIAuthOnly) {
            Clear-Variable -Name scCredentials -Scope Script
            $Script:scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $scUsername, (ConvertTo-SecureString $scPassword -AsPlainText -Force)
        }
        return
    }

    <# We have stored creds... use them!
        uri = URI to /request.php
        u = Username
        p = SecureString encoded password to the username #>
    if (Test-Path -Path $scCredentialsFileName) {
        $Local:tmp = (Get-Content -Path $scCredentialsFileName) -join "`n" | ConvertFrom-Json
        Clear-Variable -Name scCredentials -Scope Script
        $Script:scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $Local:tmp.u, (ConvertTo-SecureString $Local:tmp.p -Key $scCredentialsKey)
        $Script:scURI = $Local:tmp.uri
        
        Output-Debug $Script:scCredentials.GetNetworkCredential().UserName
        Output-Debug $Script:scCredentials.GetNetworkCredential().Password
        Output-Debug $Script:scURI
    }
    else { # Gotta make them!
        $Local:tmp = $false
        $Local:exitCount = 3
        while ($Local:tmp -ne $true) {
            try {
                Clear-Variable -Name scCredentials -Scope Script
                $Script:scCredentials = Get-Credential -Message "Enter the account to use for SecurityCenter API access."
                if ($Script:scCredentials.GetNetworkCredential().Password -ne "") {
                    $Local:tmp = $true
                }
            }
            catch [System.Management.Automation.RuntimeException] {  # Highly likely the user hit cancel
                if ($Local:exitCount-- -lt 2) {
                    break
                }
                Write-Host No credentials detected... enter credentials... $Local:exitCount more to cancel...
            }
        } # End credential capture loop
        if ($Script:scURI -eq "") {
            $Script:scURI = Read-Host -Prompt "The SecurityCenter URI ... please enter the full URI to the SecurityCenter (w/o trailing slash)"
            # Pre-make the base REST API URI
            $Script:scURI = $Script:scURI + "/rest/"
        }
        $Local:expCreds = @{}
        <#if ($scriptDebug) {
            $Script:scCredentials.GetNetworkCredential().UserName
            $Script:scCredentials.GetNetworkCredential().Password
            Pause-Script
        }#>
        $Local:expCreds.Add("u",$scCredentials.UserName)
        $Local:expCreds.Add("p",(ConvertFrom-SecureString $scCredentials.Password -Key $scCredentialsKey))
        $Local:expCreds.Add("uri", $Script:scURI)
        $Local:expCreds | ConvertTo-Json | Out-File -FilePath $scCredentialsFileName
    }
}


function SC-BuildQueryString {
    param($queryJSON);

    $reqStr = "?"
    foreach ($Local:item in $queryJSON.GetEnumerator()) {
        $reqStr += $Local:item.Name + '=' + [System.Web.HttpUtility]::UrlEncode($Local:item.Value) + '&'
    }
    $reqStr = $reqStr.TrimEnd('&')
    # Generate the request string
    # $reqStr = [System.Web.HttpUtility]::UrlEncode(($reqStr))
    
    return $reqStr;
}


<#
    $scJSONInput is hash table/object @{}
#>
function SC-Connect {
    param(
        <# What are we trying to accomplish/get via the API? #>
        [ValidateSet("auditFile", "config", "credential", "currentUser", "currentOrganization", "feed", "file/upload",
        "group", "ipInfo", "lce", "lce/eventTypes", "scanner", "organization", "passivescanner", "plugin", "pluginFamily",
        "query", "repository", "role", "scan", "policy", "scanResult", "zone", "status", "system", "ticket", "token",
        "reportDefinition", "scanResult/import")]
          [string]$scResource,
        [ValidatePattern("^\d+")]
          [int]$scResourceID,
        <# Which HTTP Method are we using? #>
        [ValidateSet("GET","POST","DELETE")]
          [string]$scHTTPMethod,
        $scQueryString, 
        $scJSONInput,
        $scAdditionalHeadersDict = @{},
        $scRawRequestPayload
    );
    <#
        Undocumented scResource values:
        - reportDefinition
    #>

    $json = $scJSONInput | ConvertTo-Json -Compress

    # If we have a token, then the X-SecurityCenter header must be set
    if ($script:scToken -eq "") { $http_headers=@{} }
    else {
        $http_headers = @{"X-SecurityCenter"=$script:scToken}
        # Do we need to add any additional headers?
        if ($scAdditionalHeadersDict.Count -gt 0) {
            $http_headers += $scAdditionalHeadersDict
        }
    }

    # Send it.
    if ($scHTTPMethod -eq "POST") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $scResource
            if ($scResource -eq "file/upload") {
                $script:scResponse = (Invoke-RestMethod -Verbose -Uri $Local:tmpUri -Method POST -CertificateThumbprint $chosenCertThumb -Body $scRawRequestPayload -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
            }
            else {
                $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -CertificateThumbprint $chosenCertThumb -Body $json -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
            }
        }
    }
    elseif ($scHTTPMethod -eq "GET") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID + $scQueryString }
        else { $Local:tmpUri = $scURI + $scResource + $scQueryString }
        $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method GET -CertificateThumbprint $chosenCertThumb -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
    }
    else {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $scResource }
        $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method DELETE -CertificateThumbprint $chosenCertThumb -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
    }
    # Write-Host("Received: " + $Script:scResponse)
    # Write-Host(">>RESPONSE CONTENTS<< ::: " + $Script:scResponse.response)
    if ($scResource -in ("token", "system")) {
        $script:scToken = $scResponse.response.token;
    }
}


function SC-Authenticate() {
    # First try authenticating via PKI
    $script:chosenCertThumb = Invoke-CertificateChooser
    SC-Authenticate-PKI
    # If that doesn't work, try authenticating via username/password
    if ($script:scToken -eq "") {
        if (!$scPKIAuthOnly) {
            SC-Authenticate-UsernamePassword
        }
        else {
            throw "Could not get the SecurityCenter token with PKI Auth, and `$scPKIAuthOnly is True."
        }
    }
}


function SC-Authenticate-PKI() {
    SC-Connect -scResource "system" -scHTTPMethod GET
}


function SC-Authenticate-UsernamePassword() {
    $json = @{}
    $json.Add("username", $scCredentials.GetNetworkCredential().UserName)
    $json.Add("password", $scCredentials.GetNetworkCredential().Password)
    SC-Connect -scResource "token" -scHTTPMethod POST -scJSONInput $json

    $script:scToken = $script:scResponse.response.token
}


function SC-Logout {
    SC-Connect -scResource "token" -scHTTPMethod DELETE
}


function SC-Get-Status() {
    SC-Connect -scResource status -scHTTPMethod GET
    return $script:scResponse.response
}


function SC-Get-Repositories() {
    <#
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Repository.html
    #>
    param (
        #`id` always comes back
        [switch]$name,
        [switch]$description,
        [ValidateSet("All","Local","Remote","Offline")]
          [string]$type,
        [switch]$dataFormat,
        [switch]$vulnCount,
        [switch]$remoteID,
        [switch]$remoteIP,
        [switch]$running,
        [switch]$downloadFormat,
        [switch]$lastSyncTime,
        [switch]$lastVulnUpdate,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$transfer,
        [switch]$typeFields,
        [switch]$remoteSchedule
    )
    # Build the query dict
    $dict = @{
        "fields" = "id";
    }
    # Set all the fields, if they were requested to be set...
    if ($name) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",name")}
    if ($description) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",description")}
    if ($type) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",type")}
    if ($dataFormat) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",dataFormat")}
    if ($vulnCount) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",vulnCount")}
    if ($remoteID) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",remoteID")}
    if ($remoteIP) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",remoteIP")}
    if ($running) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",running")}
    if ($downloadFormat) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",downloadFormat")}
    if ($lastSyncTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",lastSyncTime")}
    if ($lastVulnUpdate) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",lastVulnUpdate")}
    if ($createdTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",createdTime")}
    if ($modifiedTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",modifiedTime")}
    if ($transfer) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",transfer")}
    if ($typeFields) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",typeFields")}
    if ($remoteSchedule) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",remoteSchedule")}

    SC-Connect -scResource repository -scHTTPMethod GET -scQueryString (SC-BuildQueryString -queryJSON $dict)
}


function SC-Upload-File() {
    <#
        A semi-loosely documented endpoint. It's documented, just not for all use-cases.
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/File.html
    #>
    param(
        $filePath
    )
    Write-Host $filePath
    # Read in the entire file
    $fileBin = [IO.File]::ReadAllBytes($filePath)
    # Safely encode the file for transfer
    $fileEnc = [System.Text.Encoding]::GetEncoding("ISO-8859-1").GetString($fileBin)
    # Make a boundary to deliniate where the file information is
    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    $fileName = (Split-Path -Leaf $filePath)
    # Manually build the request payload, doing something like ``@(foo,bar,baz) -join $LF`` adds spaces in spots and mucks it up.
    $uploadBody = "----------$boundary" + $LF
    $uploadBody += "Content-Disposition: form-data; name=`"Filedata`"; filename=`"$fileName`"$LF"
    $uploadBody += "Content-Type: application/octet-stream$LF$LF"
    $uploadBody += $fileEnc + $LF
    $uploadBody += "----------$boundary--"
    # Add in the additional headers required for this API endpoint
    $additionalHeaders = @{"Content-Type"="multipart/form-data; boundary=--------$boundary"}
    SC-Connect -scResource file/upload -scHTTPMethod POST -scAdditionalHeadersDict $additionalHeaders -scRawRequestPayload $uploadBody
    # The name of the file on the SecurityCenter server to be used for other actions (such as importing)
    return $script:scResponse.response.filename
}


function SC-Import-Nessus-Results() {
    <#
        An undocumented endpoint for importing results from an uploaded Nessus results file.

        Requires the addition of the "Content-Type:application/json" header.
    #>
    param(
        $generatedFilename,
        [ValidatePattern("^\d+")]
          [int]$repositoryID = 7
    )
    # Build the query according to what was observed in-browser
    $dict = @{
        "classifyMitigatedAge" = 0;
        "context" = "";
        "createdTime" = 0;
        "description" = "";
        "dhcpTracking" = "true";
        "filename" = "$generatedFilename";
        "groups" = @();
        "modifiedTime" = 0;
        "name" = "";
        "repository" = @{"id" = $repositoryID};
        "rolloverType" = "template";
        "scanningVirtualHosts" = "false";
        "tags" = "";
        "timeoutAction" = "import";
    }
    # Send the import request
    SC-Connect -scResource scanResult/import -scHTTPMethod POST -scJSONInput $dict -scAdditionalHeadersDict @{"Content-Type" = "application/json"}
}

# --- Functions for SC API ^/
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

# Log into the SecurityCenter...
Read-ConfigFile
SC-GetCredentials
$chosenCertThumb = Invoke-CertificateChooser
SC-Authenticate

# Then process the IP purge request...

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

# Now that we have the zipped .nessus file, upload it...
$sc_uploaded_filename = SC-Upload-File -filePath $zip_output_filename

# Then issue the command to import it.
SC-Import-Nessus-Results -generatedFilename $sc_uploaded_filename

SC-Logout

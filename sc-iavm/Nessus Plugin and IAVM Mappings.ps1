param(
    [string]$paramPKIThumbprint
)
<#
    Generates two files where there is a
    Plugin->IAVM mapping, and IAVM->Plugin mapping
    SecurityCenter API Level: v5.x
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
if ($paramPKIThumbprint) { [string]$chosenCertThumb = $paramPKIThumbprint }
$scToken = "";
$scSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession;
$scUsername = "";  # Optional; Use if not using external cred/conf file.
$scPassword = "";  # Optional; Use if not using external cred/conf file.
$scResponse = "";
$scIAVAs = @{};
$scIAVBs = @{};
$scIAVTs = @{};
$htTmpPluginToIAVM = @{};
$htTmpIAVMToPlugin = @{};
$outputFileNamePlugToIAV = "Nessus Plugin to IAVM Mapping.csv"
$outputFileNameIAVToPlug = "IAVM to Nessus Plugin Mapping.csv"
$scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList "foo", (ConvertTo-SecureString "foo" -AsPlainText -Force)
$scCredentialsFileName = ".\scCredentials.conf"
$scCredentialsKey = @();  # If changed, scCredentials.conf is invalid and must be regenerated. Can be read from conf file. 24 bytes.
$scCredentialsKeyFileName = ".\pluginIAVMMapping.conf"
$scUseExternalCredentials = $true;
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
    if ($scUseExternalCredentials -ne $true) {
        Clear-Variable -Name scCredentials -Scope Script
        $Script:scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $scUsername, (ConvertTo-SecureString $scPassword -AsPlainText -Force)
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
        [string]$scResource, 
        <# Which HTTP Method are we using? #>
        [ValidateSet("GET","POST","DELETE")]
            [string]$scHTTPMethod,
        $scQueryString, 
        $scJSONInput
    );

    $json = $scJSONInput | ConvertTo-Json -Compress

    # If we have a token, then the X-SecurityCenter header must be set
    if ($script:scToken -eq "") { $http_headers=@{} }
    else { $http_headers = @{"X-SecurityCenter"=$script:scToken} }

    # Send it.
    if ($scHTTPMethod -eq "POST") {
        $Local:tmpUri = $scURI + $scResource
        $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -CertificateThumbprint $chosenCertThumb -Body $json -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
    }
    elseif ($scHTTPMethod -eq "GET") {
        $Local:tmpUri = $scURI + $scResource + $scQueryString
        $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method GET -CertificateThumbprint $chosenCertThumb -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
    }
    else {
        $Local:tmpUri = $scURI + $scResource
        $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method DELETE -CertificateThumbprint $chosenCertThumb -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
    }
    # Write-Host("Received: " + $Script:scResponse)
    # Write-Host(">>RESPONSE CONTENTS<< ::: " + $Script:scResponse.response)
    if ($scResource -eq "token") {
        $script:scToken = $scResponse.response.token;
    }
}


function SC-Login {
    $json = @{}
    $json.Add("username", $scCredentials.GetNetworkCredential().UserName)
    $json.Add("password", $scCredentials.GetNetworkCredential().Password)
    
    SC-Connect -scResource "token" -scHTTPMethod POST -scJSONInput $json
}


function SC-Logout {
    SC-Connect -scResource "token" -scHTTPMethod DELETE
}


function SC-Get-Plugins() {
    param(
        [ValidateSet("copyright", "description", "exploitAvailable", "family", "id", "name",
                     "patchPubDate", "patchModDate", "pluginPubDate", "pluginModDate",
                     "sourceFile", "type", "version", "vulnPubDate", "xrefs")]
        [string]$filterField = "",
        [string]$xrefType = "",
        [ValidateSet("ASC", "DESC")]
          [string]$sortDirection = "DESC",
        [ValidateSet("modifiedTime", "id", "name", "family", "type")]
          [string]$sortField = "modifiedTime",
        [ValidateSet("active", "all", "compliance", "custom", "lce", "notPassive")]
          [string]$type = "all",
        [ValidatePattern("^\d+")]
          [string]$startOffset = 0,
        [ValidatePattern("^\d+")]
        [ValidateScript({$startOffset -le $_})]
          [string]$endOffset = 50,
        [ValidatePattern("^\d+")]
          [int64]$secondsSinceEpoch = 0 ,
        [ValidateSet("eq", "gt", "gte", "like", "lt", "lte")]
          [string]$op = "",
        [string]$value = "",
        [string]$fields = "id,name,xrefs"
    );
    if ($xrefType -ne "") {
        $computedFilterField = $filterField + ":" + $xrefType
    }
    <# More parameter validation... #>
    if (($filterField -ne "type") -and ($filterField -ne "")) {
        if ($op -eq "") {
            Throw "The ``op`` and ``value`` parameters must be set when ``filterField`` is defined and any other value except `'type`'."
        }
    }
    elseif (($filterField -eq "type") -and ($filterField -ne "")) {
        if ($op -eq "") {
            Throw "The ``op`` and ``value`` parameters must be set when ``filterField`` is defined and of the value `'type`'."
        }
        if ($value -notin @('active', 'passive', 'lce', 'compliance', 'custom')) {
            Throw "The allowable values for the ``value`` parameter when ``filterField`` is set to `'type`' are: active, passive, lce, compliance, custom."
        }
    }

    # Build the query dict
    $dict = @{ "sortDirection" = $sortDirection;
               "sortField" = $sortField;
               "type" = $type;
               "startOffset" = $startOffset;
               "endOffset" = $endOffset;
               "since" = $secondsSinceEpoch;
               "fields" = $fields;
             }
    # If we are using any `filterField` settings, add the corresponding name/value pairs to the dict
    if ($computedFilterField -ne "") {
        $dict.Add("filterField", $computedFilterField)
        $dict.Add("op",$op)
        $dict.Add("value",$value)
    }

    SC-Connect -scResource "plugin" -scHTTPMethod GET -scQueryString (SC-BuildQueryString -queryJSON $dict)
    return $Script:scResponse.response
}


function Process-Xref-String {
    param([string]$Type, 
          [string]$Xrefs,
          [string]$PluginID);

    $strSplit = $Xrefs.Split(" ")
    $iavTmp = "";
    foreach($z in $strSplit.GetEnumerator()) {
            #Write-Host($z)
        if ($z.StartsWith($type)) {
            $iavTmp = $z.Trim(",")
            $iavTmp = $iavTmp.Replace($type + ":","")  <# Superfluous; Kill the IAVA: IAVB: prefix #>
            #Write-Host($iavTmp)
            <### Plugin -> IAVM ID ###>
			try {$Script:htTmpPluginToIAVM.Add($PluginID, $iavTmp)}  <# Key doesn't exist yet, so add it in now #>
            catch [System.Management.Automation.MethodInvocationException] {  <# Key exists, so append the pluginID #>
                #Write-Host(">>> IAVM ID <<<" + $iavTmp)
                $qq = $Script:htTmpPluginToIAVM.Get_Item($PluginID)
                $qq = $qq + ", " + $iavTmp
                $qq = $qq.TrimStart(", ") <# Because gremlins. #>
                #Write-Host($qq)
                $Script:htTmpPluginToIAVM.Set_Item($PluginID, $qq)
            }
			<### IAVM ID -> Plugin ###>
			try {$Script:htTmpIAVMToPlugin.Add($iavTmp, $PluginID)} <# Key doesn't exist yet, so add it in now #>
            catch [System.Management.Automation.MethodInvocationException] { <# Key exists, so append the pluginID #>
                #Write-Host(">>> IAVM ID <<<" + $iavTmp)
                $qq = $Script:htTmpIAVMToPlugin.Get_Item($iavTmp)
                $qq = $qq + ", " + $PluginID
                $qq = $qq.TrimStart(", ") <# Because gremlins. #>
                #Write-Host($qq)
                $Script:htTmpIAVMToPlugin.Set_Item($iavTmp, $qq)
            }
        }
    }
}

Read-ConfigFile;
SC-GetCredentials;

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = Invoke-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

<# Gotta log in before anything! #>
Write-Host("You may be prompted for your PIN! If so, would you kindly provide it to the dialog to permit authentication? Thanks!") -ForegroundColor Green
Write-Host("Logging in; wait...")
SC-Login;
# Write-Host("We just got a /token/. We just got a \token\. We just got a |token|, I wonder what it is‽ ::: " + $scToken);

<# GET THOSE IAVMS! CHAAAARGE! #>
Write-Host("Acquiring IAVM IDs; wait...")
$Script:scIAVAs = SC-Get-Plugins -filterField xrefs -xrefType "IAVA" -endOffset 4000 -type active -op like -value "-A-"
Write-Host("Acquiring some additional IAVM IDs; wait some more...")
$Script:scIAVBs = SC-Get-Plugins -filterField xrefs -xrefType "IAVB" -endOffset 4000 -type active -op like -value "-B-"
Write-Host("Searching for any lost IAVM IDs; wait some more...")
$Script:scIAVTs = SC-Get-Plugins -filterField xrefs -xrefType "IAVT" -endOffset 4000 -type active -op like -value "-T-"

<# Done with SC at this point; cleanly close out the session #>
Write-Host("Logging out; wait...")
SC-Logout;

Write-Host("Doing magic; wait...") 
<#
    We need to ferret out the unique IAVM IDs. Hashtables have to contain unique keys.
    Values can be updated via $hashtable.Set_Item(KEY,NEWVALUE)
#>
foreach($q in $scIAVAs) { <# We'll do the A's first #>
    Process-Xref-String -Type "IAVA" -Xrefs $q.xrefs -PluginID $q.id
}
Write-Host("Doing more magic; wait...")
foreach($q in $scIAVBs) { <# Then the B's #>
    Process-Xref-String -Type "IAVB" -Xrefs $q.xrefs  -PluginID $q.id
}
Write-Host("Just a bit more more magic; wait...")
foreach($q in $scIAVTs) { <# Then the T's ... because completeness. #>
    Process-Xref-String -Type "IAVT" -Xrefs $q.xrefs  -PluginID $q.id
}

<# CSV Magicks Happen Here #>
Write-Host("Exporting Plugin-to-IAVM CSV... grab a scone if you can travel at the speed of light; otherwise, wait...")
$fileWritten = 0;
while ($fileWritten -ne 1) {
    try{
        $htTmpPluginToIAVM.GetEnumerator() | Select Name, Value | Sort-Object -Property Name -Descending | 
            Export-Csv -Path $outputFileNamePlugToIAV -NoTypeInformation
        $fileWritten++
    }
    catch [System.IO.IOException] {
        Write-Host "Unable to write file... file may be open in another process..."
        Write-Host "Press any key to continue; Ctrl+C to terminate..."
        Pause-Script
    }
}
Write-Host("Exporting IAVM-to-Plugin CSV... grab a scone if you can travel at the speed of light; otherwise, wait...")
$fileWritten = 0;
while ($fileWritten -ne 1) {
    try{
        $htTmpIAVMToPlugin.GetEnumerator() | Select Name, Value | Sort-Object -Property Name -Descending | 
            Export-Csv -Path $outputFileNameIAVToPlug -NoTypeInformation
        $fileWritten++
    }
    catch [System.IO.IOException] {
        Write-Host "Unable to write file... file may be open in another process..."
        Write-Host "Press any key to continue; Ctrl+C to terminate..."
        Pause-Script
    }
}

Write-Host("Done. Enjoy your relativistic scone.") -ForegroundColor Green
Start-Sleep -Milliseconds 420

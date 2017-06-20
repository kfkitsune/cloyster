param(
    [string]$paramPKIThumbprint
)
<#
  Automatically updates a specified SecurityCenter DNS Asset list with information
    pulled directly from Active Directory, either from a supplied AD OU LDAP string,
    or manually from user-input based on the detected location of the system at
    runtime.

  Script-level parameters:
    - paramPKIThumbprint: The PKI certificate thumbprint to use for the SecurityCenter.
        Optional, however providing the parameter will prevent the user from being
        prompted during runtime. If omitted, the user will be presented with a list of
        detected PKI certificates available for authentication.
#>


###############################################################################
#-----------------These variables are intended to be edited-------------------#
###############################################################################
$target_asset_list_id = 710
$target_asset_list_name = "* - Active Directory Export"
# Use this OU instead of asking the user which OU-level they want to use
$ou = ""
# OU patterns here will be excluded from the overall results.
$excluded_ou_patterns = { $_.DistinguishedName -notmatch ",OU=MISCELLANEOUS," }
###############################################################################


try {  ### Begin module import block ###
    Import-Module $env:USERPROFILE\Documents\AuthScripts\Modules\KFK-CommonFunctions.psm1 -ErrorAction Stop -DisableNameChecking
    Import-Module ActiveDirectory
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
$scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList "foo", (ConvertTo-SecureString "foo" -AsPlainText -Force)
$scCredentialsFileName = ".\scCredentials.conf"
$scCredentialsKey = @();  # If changed, scCredentials.conf is invalid and must be regenerated. Can be read from conf file. 24 bytes.
$scCredentialsKeyFileName = ".\pluginIAVMMapping.conf"
$scUseExternalCredentials = $true
$scPKIAuthOnly = $true
$externalConfig = $true
$scriptDebug = $false


function Convert-UnixEpoch-Timestamp() {
    <# Make a Unix epoch'd timestamp human readable. #>
    param([int]$timestamp)
    return (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0).AddSeconds($timestamp)
}


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
        "reportDefinition", "scanResult/import", "analysis", "asset")]
          [string]$scResource,
        [ValidatePattern("^\d+")]
          [int]$scResourceID,
        <# Which HTTP Method are we using? #>
        [ValidateSet("GET","POST","PATCH","DELETE")]
          [string]$scHTTPMethod,
        $scQueryString, 
        $scJSONInput,
        $scAdditionalHeadersDict = @{},
        $scRawRequestPayload
    );
    <#
        Undocumented scResource values:
        - reportDefinition
        - scanResult/import
    #>

    # Depth at 10 because the incoming dict might be more than 2 levels deep
    $json = $scJSONInput | ConvertTo-Json -Compress -Depth 10

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
        else { $Local:tmpUri = $scURI + $scResource }
        
        if ($scResource -eq "file/upload") {
            $script:scResponse = (Invoke-RestMethod -Verbose -Uri $Local:tmpUri -Method POST -CertificateThumbprint $chosenCertThumb -Body $scRawRequestPayload -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
        }
        else {
            $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -CertificateThumbprint $chosenCertThumb -Body $json -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
        }
        
    }
    if ($scHTTPMethod -eq "PATCH") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $scResource }

        $script:scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method PATCH -CertificateThumbprint $chosenCertThumb -Body $json -WebSession $scSession -TimeoutSec 180 -Headers $http_headers);
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
    # First try authenticating via PKI (if not already set)
    if ($script:chosenCertThumb -eq "") {
        $script:chosenCertThumb = Invoke-CertificateChooser
    }
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


function SC-Get-Asset-List () {
    <# Either gets a specific asset list identified by `$id`, or retrieves all asset lists. #>
    param(
        [ValidatePattern("\d+")]
        [ValidateScript({$_ -ge 0})]
          [int]$id = 0,
        [switch]$name,
        [switch]$description,
        [switch]$request,
        [switch]$creator,
        [switch]$owner,
        [switch]$ownerGroup,
        [switch]$targetGroup,
        [switch]$groups,
        [switch]$type,
        [switch]$tags,
        [switch]$context,
        [switch]$template,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$repositories,
        [switch]$ipCount,
        [switch]$assetDataFields,
        [switch]$typeFields,
        [switch]$viewableIPs
    )
    $dict = @{
        "fields" = "id";
    }
    if ($name) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",name")}
    if ($description) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",description")}
    if ($status) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",status")}
    if ($creator) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",creator")}
    if ($owner) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",owner")}
    if ($ownerGroup) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",ownerGroup")}
    if ($targetGroup) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",targetGroup")}
    if ($groups) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",groups")}
    if ($type) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",type")}
    if ($tags) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",tags")}
    if ($context) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",context")}
    if ($template) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",template")}
    if ($createdTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",createdTime")}
    if ($modifiedTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",modifiedTime")}
    if ($repositories) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",repositories")}
    if ($ipCount) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",ipCount")}
    if ($assetDataFields) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",assetDataFields")}
    if ($typeFields) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",typeFields")}
    if ($viewableIPs) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",viewableIPs")}

    if ($id -eq 0) {
        # Default case for when we want to retrieve all asset lists from the SecurityCenter
        SC-Connect -scResource asset -scHTTPMethod GET -scQueryString (SC-BuildQueryString -queryJSON $dict)
    }
    else {
        # We only want a single asset list as identified by `$id`.
        SC-Connect -scResourceID $id -scResource asset -scHTTPMethod GET -scQueryString (SC-BuildQueryString -queryJSON $dict)
    }
}


function SC-Patch-Asset-DNSList() {
    <# Modifies the asset identified by $id, changing only the passed in fields; this focuses on DNS List modification,
         but is by no means restricted to DNS-based asset lists. Consider this function an example. See API for full details. #>
    param(
        [ValidatePattern("\d+")]
        [ValidateScript({$_ -gt 0})]
          [int]$id,
        [string]$definedDNSNames = $null,
        [string]$description = $null,
        [string]$name = $null
    )
    $dict = @{}
    if ($definedDNSNames) { $dict += @{"definedDNSNames" = $definedDNSNames} }
    if ($description) { $dict += @{"description" = $description} }
    if ($name) { $dict += @{"name" = $name} }
    
    SC-Connect -scResource asset -scResourceID $id -scHTTPMethod PATCH -scJSONInput $dict
}


Read-ConfigFile
SC-GetCredentials
SC-Authenticate

SC-Get-Asset-List -id $target_asset_list_id -name
# Sanity check: Is this the asset list we're going after?
if ($scResponse.response.name -eq $target_asset_list_name) {
    if (!$ou) {  # If `$ou` is not set
        $Local:sys_dn_split = (Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName.Split(',')
        # Output the OU segments to the user, ignoring the CN= element (we don't care for OU purposes)
        for ($i = 1; $i -lt $Local:sys_dn_split.Length; $i++) { Write-Host '['$i' ]' $Local:sys_dn_split.Get([int]$i) }
        $Local:input = [int](Read-Host -Prompt "Enter the OU level to use as the SearchBase")
        # Rejoin the OU segments into a new OU string
        Clear-Variable -ErrorAction SilentlyContinue -Scope Local -Name source_ou  # Clear this beforehand to guard against multiple runs in the same session breaking things.
        foreach ($pos in $Local:input..($Local:sys_dn_split.Length - 1)) { $Local:source_ou += $Local:sys_dn_split.Get($pos) + ',' }
        $ou = $Local:source_ou.TrimEnd(',')
    }

    # Get the DNS suffix for this system (Only the zeroth-element)
    $dns_suffix = (Get-DnsClientGlobalSetting).SuffixSearchList[0]

    Write-Host -ForegroundColor Cyan "Getting information from AD; this may take a few moments..."
    $ad_results = Get-ADComputer -SearchBase $ou -SearchScope Subtree -Filter "*"
    Write-Host -ForegroundColor Cyan "AD Pull complete; continuing...`n`r"

    Write-Host -ForegroundColor Cyan "Generating list of systems to inject into the asset list..."
    Clear-Variable -Name ad_dns_system_list -ErrorAction SilentlyContinue -Scope Local
    foreach ($system in ($ad_results | Where-Object $excluded_ou_patterns)) {
        $ad_dns_system_list += $system.Name + "." + $dns_suffix + ","
    }
    $ad_dns_system_list = $ad_dns_system_list.TrimEnd(',')

    # Now edit the asset list to reflect the fresh AD pull...
    Write-Host -ForegroundColor Cyan "Saving the new asset list definition to the SecurityCenter..."
    $description = "Export last updated: " + (Get-Date -Format yyyyMMdd)
    SC-Patch-Asset-DNSList -id $target_asset_list_id -definedDNSNames $ad_dns_system_list -description $description
}
else {
    throw "Sanity check failed; asset list ID does not match expected asset list name; terminating execution"
}

SC-Logout

Write-Host -ForegroundColor Green "AD DNS Asset List Update Successful!"
Start-Sleep -Milliseconds 420

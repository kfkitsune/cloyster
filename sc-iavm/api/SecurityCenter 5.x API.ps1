<#
    Just an API shell for SecurityCenter, ya'know?
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
        "reportDefinition", "scanResult/import", "analysis")]
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


function SC-Delete-Scan() {
    param(
        [ValidatePattern("^\d+")]
          [int]$scan_id
    )
    SC-Connect -scResource scan -scResourceID $scan_id -scHTTPMethod DELETE
}


function SC-Get-Status() {
    SC-Connect -scResource status -scHTTPMethod GET
    return $script:scResponse.response
}


function SC-Get-Scans() {
    param (
        [ValidateSet("usable","managable")]
          [string]$filter = "usable",
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$ipList,
        [switch]$type,
        [switch]$policy,
        [switch]$creator
    )
    # Build the query dict
    $dict = @{
        "fields" = "id";
        "filter" = $filter
    }
    if ($name) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",name")}
    if ($description) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",description")}
    if ($status) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",status")}
    if ($ipList) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",ipList")}
    if ($type) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",type")}
    if ($policy) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",policy")}
    if ($creator) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",creator")}
    SC-Connect -scResource scan -scHTTPMethod GET -scQueryString (SC-BuildQueryString $dict)
}


function SC-Get-ReportDefinition() {
    <#
        An undocumented API endpoint.
    #>
    param(
        [int]$reportID
    )
    # Build the query dict
    $dict = @{
        "fields" = "name,type,description,ownerGroup,owner,createdTime,modifiedTime,schedule,pubSites,emailUsers,emailTargets,emailTargetType,shareUsers,canManage,canUse,definition,dataSource,scanResult,styleFamily,queryStatus,encryptionPassword,status";
    }
    SC-Connect -scResource reportDefinition -scResourceID 263 -scHTTPMethod GET -scQueryString (SC-BuildQueryString $dict)
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


function SC-Get-RepositoryIPs() {
    <#
        Not an endpoint, but a helper function to `SC-Get-Repositories` to easily extract a PSCustomObject
        containing the repository ID number, the name of said repository, and the IPs able to be imported to
        the aforementioned repository.
    #>
    SC-Get-Repositories -type All -name -typeFields
    $ret = ($scResponse.response | 
                Select-Object @{Name='repo_id';Expression={$_.id}},
                              @{Name='repo_name';Expression={$_.name}},
                              @{Name='ip_range';Expression={$_.typeFields.ipRange}}
            )
    return $ret
}


function SC-Get-ScanZone() {
    <#
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Scan-Zone.html
    #>
    param (
        #`id` always comes back
        [switch]$name,
        [switch]$description,
        [switch]$ipList,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$organizations,
        [switch]$activeScanners,
        [switch]$totalScanners,
        [switch]$scanners
    )
    $dict = @{
        "fields" = "id";
    }
    # Set all the fields, if they were requested to be set...
    if ($name) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",name")}
    if ($description) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",description")}
    if ($ipList) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",ipList")}
    if ($createdTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",createdTime")}
    if ($modifiedTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",modifiedTime")}
    if ($organizations) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",organizations")}
    if ($activeScanners) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",activeScanners")}
    if ($totalScanners) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",totalScanners")}
    if ($scanners) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",scanners")}

    # Send the request...
    SC-Connect -scResource zone -scHTTPMethod GET -scQueryString (SC-BuildQueryString -queryJSON $dict)
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


function SC-Get-DetailedVulnerabilities() {
    <#
        This is noticably slower than directly exporting a report from the UI, but it -can- be done.
        Which is reason enough to have this.
    #>
    param(
        [ValidatePattern("^\d+")]
          [int]$repository,
        [ValidatePattern("^\d+")]
          [int]$startOffset = 0,
        [ValidatePattern("^\d+")]
        [ValidateScript({$startOffset -le $_})]
          [int]$endOffset = 50
    )
    $dict = @{
        "type" = "vuln";
        "sourceType" = "cumulative";
        "query" = @{
            "context" = "";
            "createdTime" = 0;
            "description" = "";
            "startOffset" = $startOffset;
            "endOffset" = $endOffset;
            "groups" = @();
            "modifiedTime" = "0";
            "name" = "";
            "sourceType" = "cumulative";
            "status" = "-1";
            "tags" = "";
            "tool" = "vulndetails";
            "type" = "vuln";
            "vulnTool" = "vulndetails";
            "filters" = @(@{
                "filterName" = "repository"
                "id" = "repository"
                "isPredefined" = $true
                "operator" = "="
                "value" = @(@{
                    "id" = "$repository"
                })
            })
        }
    } <# End query dict building #>
    #$dict | ConvertTo-Json -Depth 10
    SC-Connect -scResource analysis -scHTTPMethod POST -scJSONInput $dict
    
    # Important items in the response: totalRecords & results
    return $scResponse.response
}


Read-ConfigFile
SC-GetCredentials
$chosenCertThumb = Invoke-CertificateChooser

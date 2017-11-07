<#"" TODO
Functions to transfer:
a) SC-BuildQueryString -- DONE/TESTED as ``_SC-BuildQueryString``
b) SC-Connect -- DONE/TESTED
c) SC-Authenticate -- DONE/TESTED(PKI) (rewritten)
d) SC-Authenticate-PKI -- DONE/TESTED as ``_SC-Authenticate-PKI``
e) SC-Authenticate-UsernamePassword -- DONE as ``_SC-Authenticate-UsernamePassword``
f) SC-Logout -- DONE/TESTED
g) SC-Get-Plugins -- DONE
h) SC-Delete-Scan -- DONE/TESTED
I) SC-Get-RolloverScans -- DONE/TESTED
j) SC-Purge-RolloverScans -- DONE/TESTED
k) SC-Get-Status -- DONE
l) SC-Get-Scans -- DONE/TESTED, renamed as ``SC-Get-ScanInfo``
m) SC-Edit-Scan --DONE
n) SC-Get-ScanPolicy --DONE
o) SC-Get-FullScanInformation - Implemented as a switch in SC-Get-ScanInfo
p) SC-Get-Repositories --DONE
q) SC-Get-RepositoryIPs -- DONE
r) SC-Get-ScanZone --DONE
s) SC-Upload-File --DONE
t) SC-Import-Nessus-Results -- DONE as ``SC-Import-NessusResults``
u) SC-Get-DetailedVulnerabilities
v) SC-Get-Asset-List -- DONE as ``SC-Get-AssetList``
w) SC-Patch-Asset-DNSList

Functions not transferring:
- function Read-ConfigFile
- function SC-GetCredentials
- SC-Get-ReportDefinition

""#>

<#
API Module for SecurityCenter 5.x
Tenable API References: 
a) https://docs.tenable.com/sccv/api/index.html
b) https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/index.html
#>

#==> ``_70DBAC67`` - a hopefully unique string to mark this module's global variables
# The URI to the REST endpoint (e.g., "https://sc.contoso.com/rest/")
$Global:scURI_70DBAC67 = ""
# The assigned token value from a system or token call
$Global:scToken_70DBAC67 = ""
# A [Microsoft.PowerShell.Commands.WebRequestSession] from the Invoke-WebRequest call that logged into the SecurityCenter
$Global:scSession_70DBAC67 = $null


function Get-DateTimeFromUnixEpoch() {
    <# Make a Unix epoch'd timestamp human readable. #>
    param([int64]$timestamp)
    return (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0).AddSeconds($timestamp)
}


function Get-UnixEpochFromDateTime() {
    param([DateTime]$datetime)
    return [int64]((New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End $datetime).TotalSeconds)
}


function _SC-BuildQueryString {
    param($queryJSON);

    $reqStr = "?"
    foreach ($Local:item in $queryJSON.GetEnumerator()) {
        $reqStr += $Local:item.Name + '=' + [System.Web.HttpUtility]::UrlEncode($Local:item.Value) + '&'
    }
    $reqStr = $reqStr.TrimEnd('&')
    
    return $reqStr;
}


function SC-Authenticate() {
    <#
        Attempt to authenticate to an account on the SecurityCenter, either via PKI, or via username/password.

        Parameters:
          - $pkiThumbprint: The PKI Thumbprint of a certificate associated with an account on the SecurityCenter.
          - $credential: a PSCredential object from which the username/password are extracted.
          - $uri: Required. The base URI to the SecurityCenter (e.g., "https://sc.contoso.com"); no trailing slash.

        Returns: Nothing(?)
        #TODO: Does script/global-level token storage work for this?
    #>
    param(
        [Parameter(Mandatory=$true, ParameterSetName="Password")]
          [System.Management.Automation.PSCredential]$credential = $null,
        [Parameter(Mandatory=$true, ParameterSetName="PKI")]
          [string]$pkiThumbprint = $null,
        [Parameter(Mandatory=$true)]
        [ValidateScript({($_ -like "https://*") -and ($_ -notlike "https://*/")})]
          [string]$uri
    )
    $Global:scURI_70DBAC67 = $uri + "/rest/"
    
    if ($pkiThumbprint -ne $null) {
        # Attempt authenticating via PKI
        _SC-Authenticate-PKI -pkiCertThumbprint $pkiThumbprint
    }
    elseif ($credential -ne $null) {
        # Attempt authenticating via username/password
        _SC-Authenticate-UsernamePassword -credential $credential
    }
}


function _SC-Authenticate-PKI() {
    <#
        Attempt authentication with a PKI Certificate.

        Parameters:
          - pkiThumbprint: The thumbprint of an available PKI keypair, likely from the ``cert:`` PoSH drive.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [string]$pkiCertThumbprint
    )
    SC-Connect -scResource "system" -scHTTPMethod GET -pkiCertThumbprint $pkiCertThumbprint
}


function _SC-Authenticate-UsernamePassword() {
    <#
        Attempt authentication with a username and password.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [System.Management.Automation.PSCredential]$credential = $null
    )

    $json = @{}
    $json.Add("username", $credential.GetNetworkCredential().UserName)
    $json.Add("password", $credential.GetNetworkCredential().Password)

    SC-Connect -scResource token -scHTTPMethod POST -scJSONInput $json
}


function _SC-Connect-CheckError($response) {
    <#
        Determines if there was an error in the ``$response`` sent back from the SecurityCenter.

        Parameters: ``$response`` - The response as received from ``SC-Connect``

        Returns: Nothing. Throws ``$response.error_msg`` if the SecurityCenter reports an error
          with the submitted request
    #>
    if ($response.error_code -ne 0) {
        throw $response.error_msg
    }
}


<#
    $scJSONInput is hash table/object @{}
#>
function SC-Connect {
    <#
        Initiate a request to the SecurityCenter.

        Parameters:
          - scResource: Required. Determines which endpoint to send this request to.
          - scResourceID: Optional. Specifically identified an object in the SecurityCenter, such as
              a specific scan, or user account to perform an action on. Must be a positive number
          - scHTTPMethod: Required. The HTTP Method to use when performing this action.
          - scQueryString: Optional. Used with HTTP GET requests. Built via ``_SC-BuildQueryString`` (or
              other syntactically valid query string mechanism).
          - scJSONInput: Optional. A dict @{} of items to be converted to JSON inside this function.
          - scAdditionalHeadersDict: Optional. Required when using certain API endpoints, such as ``file/upload``.
          - scRawRequestPayload: Optional. Required for use with ``file/upload``.
          - pkiCertThumbprint: Optional. Required if attempting to authenticate to the SecurityCenter using a
              PKI certificate. Only used for the ``/system`` endpoint.

        Returns: A JSON response object as received from the SecurityCenter.
    #>
    param(
        <# What are we trying to accomplish/get via the API? #>
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "analysis",
            "asset",
            "asset/-ID-/export",
            "auditFile",
            "config",
            "credential",
            "currentOrganization",
            "currentUser",
            "feed",
            "file/upload",
            "group",
            "ipInfo",
            "lce",
            "lce/eventTypes",
            "organization",
            "passivescanner",
            "plugin",
            "pluginFamily",
            "policy",
            "policy/-ID-/export",
            "query",
            "reportDefinition",
            "reportDefinition/-ID-/export",
            "repository",
            "repository/-ID-/ipInfo",
            "role",
            "scan",
            "scanner",
            "scanResult",
            "scanResult/import",
            "status",
            "system",
            "ticket",
            "token",
            "user",
            "zone"
        )]
          [string]$scResource,
        [ValidatePattern("^\d+$")]
          [int]$scResourceID,
        <# Which HTTP Method are we using? #>
        [Parameter(Mandatory=$true)]
        [ValidateSet("GET","POST","PATCH","DELETE")]
          [string]$scHTTPMethod,
        $scQueryString,
        $scJSONInput,
        $scAdditionalHeadersDict = @{},
        $scRawRequestPayload,
        [string]$pkiCertThumbprint = '-1'
    );
    <#
        Undocumented scResource values:
        - reportDefinition
        - scanResult/import
        - reportDefinition/<reportID>/export
    #>

    # Depth at 10 because the incoming dict might be more than 2 levels deep
    $json = $scJSONInput | ConvertTo-Json -Compress -Depth 10

    # If we have a token, then the X-SecurityCenter header must be set
    if ($Global:scToken_70DBAC67 -eq "") { $http_headers=@{} }
    else {
        $http_headers = @{"X-SecurityCenter"= $Global:scToken_70DBAC67}
        # Do we need to add any additional headers?
        if ($scAdditionalHeadersDict.Count -gt 0) {
            $http_headers += $scAdditionalHeadersDict
        }
    }

    # Select endpoints operate in a manner such as /repository/{id}/ipInfo ... handle this
    # TODO: Is there a more elegant method of doing this?
    if ($scResource -like '*/-ID-/*') {
        $scResource = $scResource.Replace("-ID-", $scResourceID)
        Clear-Variable -Name $scResourceID
    }

    # Grab a local copy of the SC REST URI
    $scURI = $Global:scURI_70DBAC67

    # Send it.
    if ($scHTTPMethod -eq "POST") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $scResource }
        
        if ($scResource -eq "file/upload") {
            $scResponse = (Invoke-RestMethod -Verbose -Uri $Local:tmpUri -Method POST -Body $scRawRequestPayload -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
        elseif ($scResource -eq "token") {
            # Handle POST against ``/token`` resource (AKA, Get a token)
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $json -SessionVariable scSession -TimeoutSec 180 -Headers $http_headers);
        }
        else {
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $json -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
        
    }
    if ($scHTTPMethod -eq "PATCH") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $scResource }

        $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method PATCH -Body $json -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
    }
    elseif ($scHTTPMethod -eq "GET") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID + $scQueryString }
        else { $Local:tmpUri = $scURI + $scResource + $scQueryString }
        
        # PKI: Handle GET against ``/system`` resource (AKA, Get a token)
        if ($scResource -eq "system") {
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method GET -CertificateThumbprint $pkiCertThumbprint -SessionVariable scSession -TimeoutSec 180 -Headers $http_headers);
        }
        else {
            $scResponse = (Invoke-RestMethod -Verbose -Uri $Local:tmpUri -Method GET -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
    }
    elseif ($scHTTPMethod -eq "DELETE") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $scResource }

        $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method DELETE -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
    }
    else {
        # Catch-all for non-supported HTTP methods
        throw [System.NotImplementedException]
    }

    Write-Host("Received: " + $scResponse)
    Write-Host(">>RESPONSE CONTENTS<< ::: " + $scResponse.response)
    if ($scResource -in ("token", "system")) {
        # Store the token
        $Global:scToken_70DBAC67 = $scResponse.response.token;
        # Store the session
        $Global:scSession_70DBAC67 = $scSession
    }

    # Quick and dirty error checking
    _SC-Connect-CheckError($scResponse)

    # Return the response
    return $scResponse
}


function SC-Logout {
    SC-Connect -scResource "token" -scHTTPMethod DELETE
    # We're trying to log out here; either there will be an issue, or it will succeed. Clear token either way.
    $Global:scToken_70DBAC67 = ""
}


function SC-Get-Status() {
    $resp = SC-Connect -scResource status -scHTTPMethod GET
    return $resp.response
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
        [ValidatePattern("^\d+$")]
          [string]$startOffset = 0,
        [ValidatePattern("^\d+$")]
        [ValidateScript({$startOffset -le $_})]
          [string]$endOffset = 50,
        [ValidatePattern("^\d+$")]
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

    $resp = SC-Connect -scResource "plugin" -scHTTPMethod GET -scQueryString (SC-BuildQueryString -queryJSON $dict)
    return $resp.response
}


function SC-Get-PluginInformation() {
    <#
        Retrieves the requested information for a single plugin ID number.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$pluginID,
        [switch]$name,
        [switch]$description,
        [switch]$family,
        [switch]$type,
        [switch]$copyright,
        [switch]$version,
        [switch]$sourceFile,
        [switch]$source,
        [switch]$dependencies,
        [switch]$requiredPorts,
        [switch]$requiredUDPPorts,
        [switch]$cpe,
        [switch]$srcPort,
        [switch]$dstPort,
        [switch]$protocol,
        [switch]$riskFactor,
        [switch]$solution,
        [switch]$seeAlso,
        [switch]$synopsis,
        [switch]$checkType,
        [switch]$exploitEase,
        [switch]$exploitAvailable,
        [switch]$exploitFrameworks,
        [switch]$cvssVector,
        [switch]$cvssVectorBF,
        [switch]$baseScore,
        [switch]$temporalScore,
        [switch]$stigSeverity,
        [switch]$pluginPubDate,
        [switch]$pluginModDate,
        [switch]$patchPubDate,
        [switch]$patchModDate,
        [switch]$vulnPubDate,
        [switch]$modifiedTime,
        [switch]$md5,
        [switch]$xrefs
    )
    # Build the query dict; ID number is always returned (even if id wasn't specified)
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -ne 'pluginID') {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource plugin -scResourceID $pluginID -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
}


function SC-Get-ScanPolicy() {
    <#
        Get the list of defined policies on the SecurityCenter.

        API Reference: https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Scan-Policy.html

        Endpoint: /rest/policy
    #>
    param(
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$policyTemplate,
        [switch]$policyProfileName,
        [switch]$creator,
        [switch]$tags,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$context,
        [switch]$generateXCCDFResults,
        [switch]$auditFiles,
        [switch]$preferences,
        [switch]$targetGroup
    )
    # Build the query dict; ID number is always returned (even if id wasn't specified)
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        # Load the switch name into the fields
        $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
    }

    # Name/Description/Status come back by default if no fields are requested
    if (!($name -or $description -or $status -or $policyTemplate -or $policyProfileName -or $creator -or
          $tags -or $createdTime -or $modifiedTime -or $context -or $generateXCCDFResults -or $auditFiles -or 
          $preferences -or $targetGroup)
          ) {
        $dict.Set_Item("fields", $dict.Get_Item("fields") + ",name,description,status")
    }

    return SC-Connect -scResource policy -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
}


function SC-Get-Repositories() {
    <#
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Repository.html
    #>
    param (
        #`id` always comes back
        [ValidateSet("All","Local","Remote","Offline")]
          [string]$type = 'All',
        [switch]$name,
        [switch]$description,
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
        "type" = $type;
        "fields" = "id"
    }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -ne 'type') {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }
    # Set all the fields, if they were requested to be set...

    return SC-Connect -scResource repository -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
}


function SC-Get-RepositoryIPs() {
    <#
        Not an endpoint, but a helper function to `SC-Get-Repositories` to easily extract a PSCustomObject
        containing the repository ID number, the name of said repository, and the IPs able to be imported to
        the aforementioned repository.
    #>
    $ret = SC-Get-Repositories -type All -name -typeFields
    return ($ret.response | Select-Object @{Name='repo_id';Expression={$_.id}},
                                          @{Name='repo_name';Expression={$_.name}},
                                          @{Name='ip_range';Expression={$_.typeFields.ipRange}}
    )
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
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        # Load the switch name into the fields
        $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
    }

    # Send the request...
    return SC-Connect -scResource zone -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
}


function SC-Delete-Scan() {
    <#
        Deletes a scan item from the SecurityCenter, as specified by the scan's ID number.

        Parameter: scan_id: The ID of the scan to be deleted.

        Returns: Boolean $true upon success, otherwise Boolean $false.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$scan_id
    )
    $resp = SC-Connect -scResource scan -scResourceID $scan_id -scHTTPMethod DELETE

    return !$resp.error_code
}


function SC-Get-ScanInfo() {
    <#
        Retrieves information about single or multiple scans. ``id``, if set, will return
          information specifically about the scan with that ID number.

        Parameters:
          - id: Integer; If specified, only retrieve information about the scan with the ID number given.
              otherwise, retrieve all scans' info.
          - filter: Only retrieve usable, managable, or both usable and managable scans. Defaults
              to both usable and managable scans returned.
          - getAllInfo: Switch; if specified, sets all switches to True to return all info
    #>
    param (
        [ValidatePattern("^\d+$")]
          [int]$id = 0,
        [ValidateSet("usable","managable","usable,managable")]
          [string]$filter = "usable,managable",
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$ipList,
        [switch]$type,
        [switch]$policy,
        [switch]$plugin,
        [switch]$repository,
        [switch]$zone,
        [switch]$dhcpTracking,
        [switch]$classifyMitigatedAge,
        [switch]$emailOnLaunch,
        [switch]$emailOnFinish,
        [switch]$timeoutAction,
        [switch]$scanningVirtualHosts,
        [switch]$rolloverType,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$ownerGroup,
        [switch]$creator,
        [switch]$owner,
        [switch]$reports,
        [switch]$assets,
        [switch]$credentials,
        [switch]$numDependents,
        [switch]$schedule,
        [switch]$policyPrefs,
        [switch]$maxScanTime
    )
    # Build the query dict
    $dict = @{
        "fields" = "id";
        "filter" = $filter
    }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        # Load the switch name into the `fields` (excluding non-switches)
        if ($key -notin @('id','filter')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }
    
    if (!$id) {
        # ``$id`` is zero (true), so we want to get all scans.
        return SC-Connect -scResource scan -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
    }
    else {
        # ``$id`` has been set, so we want a specific scan's information
        return SC-Connect -scResource scan -scResourceID $id -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
    }
}


function SC-Create-Scan() {
    <#
        Adds a new scan to the SecurityCenter.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [string]$name,
        [Parameter(Mandatory=$true,ParameterSetName="PluginType")]
        [Parameter(Mandatory=$true,ParameterSetName="PolicyType")]
        [ValidateSet("plugin", "policy")]
          [string]$type,
        [Parameter(Mandatory=$true,ParameterSetName="PluginType")]
        [ValidateScript({$_ -gt 0})]
          [int]$pluginID,  # Only used if ``$type`` is ``plugin``
        [Parameter(Mandatory=$true,ParameterSetName="PolicyType")]
        [ValidateScript({$_ -gt 0})]
          [int]$policyID,  # Only used if ``$type`` is ``policy``
        [string]$description = "",
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$repositoryID,
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$scanZoneID = 0,
        [ValidateSet("true", "false")]
          [string]$dhcpTracking = "false",
        [ValidateSet(0,1,2,3,4,5,6,30,60,90,365)]
          [int]$classifyMitigatedAge = 0,
        $reports = @(),  # Not yet implemented
        [ValidateScript({$_ -gt 0})]
          [int[]]$assetListIDs = @(),
        [ValidateScript({$_ -gt 0})]
          [int[]]$credentialIDs = @(),
        [ValidateSet("true", "false")]
          [string]$emailOnLaunch = "false",
        [ValidateSet("true", "false")]
          [string]$emailOnFinish = "false",
        [ValidateSet("discard", "import", "rollover")]
          [string]$timeoutAction = "import",
        [ValidateSet("nextDay", "template")]
          [string]$rolloverType = "template",
        [ValidateSet("true", "false")]
          [string]$scanningVirtualHosts = "false",
        [ValidateScript({$_ -gt 0})]  # In hours
          [int]$maxScanTime = 3600,
        [string]$ipList = "",  # Can be a CSV IP and/or FQDN list (e.g., "1.1.1.1,box.contoso.com")
        [ValidateSet("template", "dependent", "ical", "never", "rollover")]
          [string]$schedule = "template",
        # If ``type`` is ``ical``, the following are required:
        [DateTime]$startDateTime,
        [ValidateSet("ONCE","DAILY","WEEKLY","MONTHLY")]
          [string]$repeatRuleFreq = "ONCE",
        [ValidateScript({($_ -gt 0) -and ($_ -le 20)})]
          [string]$repeatRuleInterval = 1,
        [ValidateSet("SU","MO","TU","WE","TH","FR","SA")]
          [string[]]$repeatRuleByDay = "MO",
        [int]$repeatRuleNthDayOfTheWeek = -1,  # e.g., first Monday of every Month (1MO), Tuesday (1TU), etc.
        [int]$repeatRuleDayOfTheMonth = -1,  # e.g., repeat every month on day N
        # If ``type`` is ``dependent`` the following is required:
        [ValidateScript({$_ -gt 0})]
          [int]$dependentScanID = $null
    )
    # Begin loading the parameters into the POST storage
    $dict = @{}

    $dict += @{ "name" = $name }
    $dict += @{ "type" = $type }
    if ($type -eq "plugin") {
        if (!$pluginID) { throw "Plugin type is selected, but no pluginID specified." }
        $dict += @{ "pluginID" = $pluginID }
    }
    elseif ($type -eq "policy") {
        if (!$policyID) { throw "Policy type is selected, but no policyID specified." }
        $dict += @{ "policy" = @{ "id" = $policyID } }
    }
    $dict += @{ "description" = $description }
    $dict += @{ "repository" = @{ "id" = $repositoryID } }
    $dict += @{ "zone" = @{ "id" = $scanZoneID } }
    $dict += @{ "dhcpTracking" = $dhcpTracking }
    $dict += @{ "classifyMitigatedAge" = $classifyMitigatedAge }
    # Generate the schedule component
    if (($schedule -eq "ical") -or ($schedule -eq "dependent")) {
        $dict += (_GenerateScanScheduleJSONComponent -schedule $schedule -startDateTime $startDateTime -repeatRuleFreq $repeatRuleFreq -repeatRuleInterval $repeatRuleInterval `
            -repeatRuleByDay $repeatRuleByDay -repeatRuleNthDayOfTheWeek $repeatRuleNthDayOfTheWeek `
            -repeatRuleDayOfTheMonth $repeatRuleDayOfTheMonth -dependentScanID $dependentScanID
        )
    }
    else {
        $dict += @{ "schedule" = $schedule }
    }
    $dict += @{ "reports" = @() }
    # Generate the Assets ID block
    if ($assetListIDs) {
        $assets = @()
        foreach ($asset in $assetListIDs) {
            $assets += @{ "id" = $asset }
        }
        $dict += @{ "assets" = $assets }
    } else { $dict += @{ "assets" = @() } }
    # Generate the Credential ID block
    if ($credentialIDs) {
        $creds = @()
        foreach ($id in $credentialIDs) {
            $creds += @{ "id" = $id }
        }
        $dict += @{ "credentials" = $creds }
    } else { $dict += @{ "credentials" = @() } }
    $dict += @{ "emailOnLaunch" = $emailOnLaunch }
    $dict += @{ "emailOnFinish" = $emailOnFinish }
    $dict += @{ "timeoutAction" = $timeoutAction }
    $dict += @{ "scanningVirtualHosts" = $scanningVirtualHosts }
    $dict += @{ "rolloverType" = $rolloverType }
    $dict += @{ "ipList" = $ipList }
    $dict += @{ "maxScanTime" = $maxScanTime }

    # TODO: Finish this function. It's not yet ready (or tested).
    return $dict
}


function _GenerateScanScheduleJSONComponent() {
    <#
        Constructs the ``schedule`` object for a scan request

        Monthly scans are special and follow the rules below:
          - To conduct a scan on the Nth-day of the week, set ``repeatRuleNthDayOfTheWeek`` to the week-number (1-4), and
              ``repeatRuleByDay`` to the weekday on which the scan should run.
          - To conduct a scan every Nth-day of the month (e.g., every first of the month), set ``repeatRuleDayOfTheMonth``
              to the day on which the scan should be run monthly.

        Parameters:
          - schedule: The schedule type. This function processes `ical` and `dependent` types
          - startDateTime: A DateTime object. Rounds **up** to the nearest 30 minute interval (respecting the SC UI's time bounds).
          - repeatRuleFreq: How often should the scan run? Defaults to Once; Options are (Once, Daily, Weekly, Monthly)
          - repeatRuleInterval: On frequencies other than `Once`, how often should this scan execute. Unit of time is
              indicated in the same units as the Frequency. E.g., every 2 days, every 2 weeks, every 2 months.
          - repeatRuleByDay: A [String] array of days on which to run scans on the 'DAILY' Frequency. Defaults to MO = Monday.
          - repeatRuleNthDayOfTheWeek: On the Monthly frequency, specifies the week-number on which the scan executes. E.g,
              run the scan on the Fourth Friday of each month. Must be specified with ``repeatRuleByDay`` (one element)
          - repeatRuleDayOfTheMonth: On the Monthly frequency, specifies on which day the scan is to run, such as the first
              of every month.
          - dependentScanID: If ``schedule`` is of type `dependent`, the dependent scan ID to chain this schedule object to.
    #>
    param(
        [ValidateSet("ical", "dependent")]
          [string]$schedule,
        [DateTime]$startDateTime,
        [ValidateSet("ONCE", "DAILY", "WEEKLY", "MONTHLY")]
          [string]$repeatRuleFreq = "ONCE",
        [ValidateScript({($_ -gt 0) -and ($_ -le 20)})]
          [string]$repeatRuleInterval = 1,
        [ValidateSet("SU", "MO", "TU", "WE", "TH", "FR", "SA")]
          [string[]]$repeatRuleByDay = "MO",
        [ValidateSet(-1, 1, 2, 3, 4)]
        [int]$repeatRuleNthDayOfTheWeek = -1,  # e.g., first Monday of every Month (1MO), Tuesday (1TU), etc.
        [int]$repeatRuleDayOfTheMonth = -1,  # e.g., repeat every month on day N
        [ValidateScript({$_ -ge -1})]
          [int]$dependentScanID = -1
    )
    if ($schedule -eq "ical") {
        # Process the ``repeatRule`` component of the ``schedule`` object...
        if ($repeatRuleFreq -eq "MONTHLY") {
            #Write-Host($repeatRuleDayOfTheWeek -eq -1)
            if ( ($repeatRuleNthDayOfTheWeek -ne -1) -and ($repeatRuleDayOfTheMonth -ne -1) ) {
                throw "Cannot determine correct repeat rule (repeatRuleDayOfTheWeek and repeatRuleDayOfTheMonth are both set)"
            }
            elseif ( ($repeatRuleNthDayOfTheWeek -eq -1) -and ($repeatRuleDayOfTheMonth -ne -1) ) {
                $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval + ";BYMONTHDAY=" + $repeatRuleDayOfTheMonth
            }
            elseif ( ($repeatRuleNthDayOfTheWeek -ne -1) -and ($repeatRuleDayOfTheMonth -eq -1) ) {
                $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval + ";BYDAY=" + $repeatRuleNthDayOfTheWeek + $repeatRuleByDay[0]
            }
        }
        elseif ($repeatRuleFreq -eq "WEEKLY") {
            $_byDay = @()
            foreach ($day in $repeatRuleFreq) {
                # Join any days into a single string array
                $_byDay += $day
            }
            $_byDay = $_byDay | Get-Unique
            $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval + ";BYDAY=" + $_byDay
        }
        elseif ($repeatRuleFreq -eq "DAILY") {
            $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval
        }
        else {
            # One-time scan, so no repeatRule needed
            $_repeatRule = ""
        }

        # Process the date... Temp timezone until I figure out how I want to expand this...
        if (($startDateTime.Minute % 30) -ne 0) {
            # Round upwards to the nearest 30 minutes (respect the UI interface's limitations)
            $diff = (30 - ($startDateTime.Minute % 30))
            $startDateTime = $startDateTime.AddMinutes($diff)
        }
        $_tzone = "America/New_York"
        $_start = "TZID=" + $_tzone + ":" + (Get-Date $startDateTime -Format yyyyMMddTHHmm00)
    }
    elseif ($schedule -eq "dependent") {
        $_repeatRule = "FREQ=undefined;INTERVAL=1"
        $_date = (Get-Date).AddDays(2)
        $_start = (Get-Date $_date -Format MM/dd/yyyy)
    }
    else { throw [System.NotImplementedException] }  # We should **not** get to this block.
    
    # Construct/return the ``schedule`` object
    $_schedule = @{
            "start" = $_start;
            "repeatRule" = $_repeatRule;
            "type" = $schedule;
    }
    if ($schedule -eq "dependent") {
        if ($dependentScanID -ne -1) {
            $_schedule += @{ "dependentID" = $dependentScanID }
        }
        else {
            # Dependent scans **must** have the dependentScanID set
            throw "Cannot schedule a Dependent-type scan when `$dependentScanID is not set."
        }
    }

    return @{ 
        "schedule" = $_schedule
    }
}


function SC-Edit-Scan() {
    <#
        Edit the scan with an ID ``id``, changing only passed in fields. Not fully implemented from the API reference.
        API Reference: https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Scan.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$id,
        [ValidateScript({$_ -gt 0})]
          [int]$newPolicyID = $null,
        [ValidateScript({($_.Length -le 1024) -and ($_.Length -ge 1)})]
          [string]$newName = $null,
        [string]$newDescription = $null,
        [ValidateScript({$_ -gt 0})]
          [int]$newImportRepositoryID = $null,
        [ValidateScript({$_ -gt 0})]
          [int]$newScanZoneID = $null,
        [ValidateSet("true","false")]
          [string]$newEmailOnLaunch = $null,
        [ValidateSet("true","false")]
          [string]$newEmailOnFinish = $null,
        [ValidateSet("discard", "import", "rollover")]
          [string]$newTimeoutAction = $null,
        [ValidateSet("true","false")]
          [string]$newScanningVirtualHosts = $null,
        [ValidateSet("nextDay", "template")]
          [string]$newRolloverType = $null,
        [ValidateScript({$_ -gt 0})]  # In hours
          [int]$newMaxScanTime = $null,
        [ValidateSet("true","false")]
          [string]$newDHCPTracking = $null,
        [ValidateSet(0,1,2,3,4,5,6,30,60,90,365)]
          [int]$newClassifyMitigatedAge = $null,
        [Parameter(ParameterSetName="credentials")]
        [ValidateScript({$_ -gt 0})]
          [int[]]$newCredentialIDs = $null,
        [Parameter(ParameterSetName="credentials")]
          [switch]$clearCredentials,
        [string]$newIPList = $null,
        [Parameter(ParameterSetName="assets")]
        [ValidateScript({$_ -gt 0})]
          [int[]]$newAssets = $null,
        [Parameter(ParameterSetName="assets")]
        [switch]$clearAssets
        # NYI: schedule, reports
    )
    $dict = @{}
    if ($newPolicyID) { $dict += @{ "policy" = @{"id" = $newPolicyID} } }
    if ($newName) { $dict += @{ "name" = $newName } }
    if ($newDescription) { $dict += @{ "description" = $newDescription } }
    if ($newImportRepositoryID) { $dict += @{ "repository" = @{"id" = $newImportRepositoryID} } }
    if ($newScanZoneID) { $dict += @{ "zone" = @{"id" = $newScanZoneID} } }
    if ($newEmailOnLaunch) { $dict += @{ "emailOnLaunch" = $newEmailOnLaunch } }
    if ($newEmailOnFinish) { $dict += @{ "emailOnFinish" = $newTimeoutAction } }
    if ($newTimeoutAction) { $dict += @{ "timeoutAction" = $newDescription } }
    if ($newScanningVirtualHosts) { $dict += @{ "scanningVirtualHosts" = $newScanningVirtualHosts } }
    if ($newRolloverType) { $dict += @{ "rolloverType" = $newRolloverType } }
    if ($newIPList) { $dict += @{ "ipList" = $newIPList } }
    if ($newMaxScanTime) { $dict += @{ "maxScanTime" = $newMaxScanTime } }
    if ($newDHCPTracking) { $dict += @{ "dhcpTracking" = $newDHCPTracking } }
    if ($newClassifyMitigatedAge) { $dict += @{ "classifyMitigatedAge" = $newClassifyMitigatedAge } }
    if ($newCredentialIDs) {  # Build the credentials subset
        $creds = @()
        foreach ($credentialID in $newCredentialIDs) {
            $creds += @{ "id" = $credentialID }
        }
        $dict += @{ "credentials" = $creds }
    }
    if ($clearCredentials) { $dict += @{ "credentials" = @() } }
    if ($newAssets) { # Build the assets subset
        $assets = @()
        foreach ($assetID in $newAssets) {
            $assets += @{ "id" = $assetID }
        }
        $dict += @{ "assets" = $assets }
    }
    if ($clearAssets) { $dict += @{ "assets" = @() } }

    # We must have something to change before we send (more validation)
    if ($dict.Count -eq 0) {
        throw "A scan setting must be edited during a call to SC-Edit-Scan; no settings provided (`$dict is empty)"
    }

    #Write-Host ($dict | ConvertTo-Json -Depth 10 -Compress)
    return SC-Connect -scResource scan -scResourceID $id -scHTTPMethod PATCH -scJSONInput $dict
}


function SC-Get-RolloverScans() {
    <# Find any rollover scans #>
    $resp = SC-Get-ScanInfo -filter managable -name -schedule -ownerGroup -owner -createdTime
    return $resp.response.manageable | Where-Object { $_.schedule.type -eq "rollover" }
}


function SC-Purge-RolloverScans() {
    <# Purge any and all rollover scans that are detected in the SecurityCenter #>
    $rollover_scans = SC-Get-RolloverScans
    $curr_count = 0
    foreach ($scan in $rollover_scans) {
        $progress = ($curr_count++ / $rollover_scans.Count) * 100
        Write-Progress -Activity "Purging all Rollover scans" -Status ("Percent complete: " + $progress + "%") -PercentComplete $progress
        Write-Host ("Purging: {id = " + $scan.id + "; name = `"" + $scan.name + "`"; owner = `"" + $scan.owner.username + "`"}")
        SC-Delete-Scan -scan_id $scan.id | Out-Null
    }
}


function SC-Upload-File() {
    <#
        A semi-loosely documented endpoint. It's documented, just not for all use-cases.
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/File.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        $filePath
    )
    # Write-Host $filePath
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


function SC-Import-NessusResults() {
    <#
        An undocumented endpoint for importing results from an uploaded Nessus results file.

        Requires the addition of the "Content-Type:application/json" header.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [string]$generatedFilename,
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
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
    return SC-Connect -scResource scanResult/import -scHTTPMethod POST -scJSONInput $dict -scAdditionalHeadersDict @{"Content-Type" = "application/json"}
}


function SC-Get-FeedInformation() {
    <#
        Gets the status of feed uploads (last update time, is it stale, and is an update running).
        Displays info for all feeds (sc, active, passive, lce).

        Parameters: None

        Returns: As it says in the function description.

        https://docs.tenable.com/sccv/api/Feed.html
    #>
    return SC-Connect -scResource feed -scHTTPMethod GET
}


function SC-Get-AssetList () {
    <# Either gets a specific asset list identified by `$id`, or retrieves all asset lists. #>
    param(
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
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    if ($id -eq 0) {
        # Default case for when we want to retrieve all asset lists from the SecurityCenter
        return SC-Connect -scResource asset -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
    }
    else {
        # We only want a single asset list as identified by `$id`.
        return SC-Connect -scResourceID $id -scResource asset -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
    }
}


function SC-Export-ReportDefinition() {
    <#
        Exports the report definition for a specified report ID, optionally maintaining references to SecurityCenter specific objects,
        stripping them, or inserting placeholders.

        Rest endpoint: /rest/reportDefinition/<reportID>/export

        Note: Undocumented endpoint, either in the SCCV or Cerberus variant of the API links

        Parameters:
          - reportID: The report ID of the report to be exported, as seen in the /#reports URI if visiting from the Web UI.
          - type: One of:
            > full: Maintains the references, if any, exactly as defined in the SecurityCenter. Suitable to import back into the same
                SecurityCenter without issues.
            > placeholder: Strips SecurityCenter specific references (repoID, assetIDs, etc.), and inserts placeholder information
                into the report template's definition.
            > cleansed: Fully strips references, leaving no placeholders.

        Returns: An XML file with the definition of the report as specified by ``reportID``, and obeying the ``type`` selection.

        # TODO: Verify this returns a raw XML file without being buried in the .response
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$reportID,
        [Parameter(Mandatory=$true)]
        [ValidateSet("full", "placeholder","cleansed")]
          [string]$type
    )
    $dict = @{ "exportType" = $type }

    return SC-Connect -scResource reportDefinition/-ID-/export -scResourceID $reportID -scHTTPMethod POST -scJSONInput $dict
}


function SC-Export-AssetList() {
    <#
        Exports the Asset associated with ``assetListID`` as plain text XML.

        Parameters: assetListID: The asset list's ID to export.

        Returns: An XML copy of the asset list, suitable for importing to the SecurityCenter.

        Note: Documented in the Cerberus-variant API reference, not the SCCV
        URI: https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Asset.html
        Endpoint: /asset/{id}/export
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$assetListID
    )
    return SC-Connect -scResource asset/-ID-/export -scResourceID $assetListID -scHTTPMethod GET
}


function SC-Get-User() {
    <#
        Retrieves user information from the SecurityCenter, returning the specified fields.
    #>
    param(
        [switch]$username,
        [switch]$firstname,
        [switch]$lastname,
        [switch]$status,
        [switch]$role,
        [switch]$title,
        [switch]$email,
        [switch]$address,
        [switch]$city,
        [switch]$state,
        [switch]$country,
        [switch]$phone,
        [switch]$fax,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$lastLogin,
        [switch]$lastLoginIP,
        [switch]$mustChangePassword,
        [switch]$locked,
        [switch]$failedLogins,
        [switch]$authType,
        [switch]$fingerprint,
        [switch]$password,
        [switch]$description,
        [switch]$canUse,
        [switch]$canManage,
        [switch]$managedUsersGroups,
        [switch]$managedObjectsGroups,
        [switch]$preferences,
        [switch]$ldaps,
        [switch]$ldapUsername
    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource user -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
}


function SC-Export-ScanPolicy() {
    <#
        Exports the scan policy as identified by ``scanPolicyID` and returns the XML representation of the policy,
        which can then be imported or archived.

        Parameters: scanPolicyID: The ID of the scan policy to export.

        Returns: An XML file representing the specified scan policy.

        Note: Documented in the Cerberus variant of the API, not the SCCV
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Scan-Policy.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$scanPolicyID
    )

    return SC-Connect -scResource policy/-ID-/export -scResourceID $scanPolicyID -scHTTPMethod POST
}


function SC-Get-GroupInformation() {
    <#
        Get a list of all groups from SecurityCenter, with the specified information.

        Parameters: See the switches in the param() block.

        Returns: A list of all groups with the specified information.

        https://docs.tenable.com/sccv/api/Group.html
    #>
    param(
        [switch]$name,
        [switch]$description,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$lces,
        [switch]$repositories,
        [switch]$definingAssets,
        [switch]$userCount,
        [switch]$users,
        [switch]$assets,
        [switch]$policies,
        [switch]$queries,
        [switch]$credentials,
        [switch]$dashboardTabs,
        [switch]$arcs,
        [switch]$auditFiles
    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource group -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
}


function SC-Get-RoleInformation() {
    <#
        Returns a list of role information with the specified fields being returned.

        Parameters: See the param() block for a full list of switches.

        Returns: As in the function description.

        https://docs.tenable.com/sccv/api/Role.html
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Role.html
    #>
    param(
        [switch]$name,
        [switch]$description,
        [switch]$creator,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$permManageApp,
        [switch]$permManageGroups,
        [switch]$permManageRoles,
        [switch]$permManageImages,
        [switch]$permManageGroupRelationships,
        [switch]$permManageBlackoutWindows,
        [switch]$permManageAttributeSets,
        [switch]$permCreateTickets,
        [switch]$permCreateAlerts,
        [switch]$permCreateAuditFiles,
        [switch]$permCreateLDAPAssets,
        [switch]$permCreatePolicies,
        [switch]$permPurgeTickets,
        [switch]$permPurgeScanResults,
        [switch]$permPurgeReportResults,
        [switch]$permScan,
        [switch]$permAgentsScan,
        [switch]$permShareObjects,
        [switch]$permUpdateFeeds,
        [switch]$permUploadNessusResults,
        [switch]$permViewOrgLogs,
        [switch]$permManageAcceptRiskRules,
        [switch]$permManageRecastRiskRules,
        [switch]$organizationCounts
    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource role -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
}


function SC-Get-CredentialInformation() {
    <#
        Gets a list of all credentials from the SecurityCenter with all specified fields. If ``credentialID`` is provided,
        only return information for the credential with the ID number ``credentialID``

        Parameters:
          - credentialID: Optional. If specified, only return information for the credential whose ID number matches
              the number provided. Integer.
          - <switches>: See param() block below for information that can be returned.
    #>
    param(
        [ValidateScript({$_ -ge 0})]
          [int]$credentialID = $null,
        [switch]$name,
        [switch]$description,
        [switch]$type,
        [switch]$creator,
        [switch]$target,
        [switch]$groups,
        [switch]$typeFields,
        [switch]$tags,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$canUse,
        [switch]$canManage,
        # Session user role not "1" (Administrator)
        [switch]$owner,
        [switch]$ownerGroup,
        [switch]$targetGroup

    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('credentialID')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    if ($credentialID -eq $null) {
        $resp = SC-Connect -scResource credential -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
    }
    else {
        # Only a specified credential is being requested.
        $resp = SC-Connect -scResource credential -scResourceID $credentialID -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
    }
    return $resp
}


function SC-Get-ScanResults() {
    <#
        Gets the list of Scan Results. The `progress` of a scan can be returned if a ``scanResultID`` is provided.

        Parameters:
          - scanResultID: The ID of a scan result entry. Required to return the `progress` of the scan. Optional. Int.
          - <switches>: See param() block below for information that can be returned.

        Returns: A list of all scans, or a single entry with the requested information
    #>
    param(
        [ValidateScript({$_ -ge 0})]
          [int]$scanResultID = $null,
        [ValidateSet("usable", "manageable", "usable,managable")]
          [string]$filterAccess = "usable,managable",
        [ValidateSet("running", "completed", "running,completed")]
          [string]$filterStatus = "running,completed",
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$initiator,
        [switch]$owner,
        [switch]$ownerGroup,
        [switch]$repository,
        [switch]$scan,
        [switch]$job,
        [switch]$details,
        [switch]$importStatus,
        [switch]$importStart,
        [switch]$importFinish,
        [switch]$importDuration,
        [switch]$downloadAvailable,
        [switch]$downloadFormat,
        [switch]$dataFormat,
        [switch]$resultType,
        [switch]$resultSource,
        [switch]$running,
        [switch]$errorDetails,
        [switch]$importErrorDetails,
        [switch]$totalIPs,
        [switch]$scannedIPs,
        [switch]$startTime,
        [switch]$finishTime,
        [switch]$scanDuration,
        [switch]$completedIPs,
        [switch]$completedChecks,
        [switch]$totalChecks,
        [switch]$progress
    )
    $filter = $filterAccess + ',' + $filterStatus

    $dict = @{ "fields" = "id";
               "filter" = $filter
    }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('scanResultID', 'filterAccess', 'filterStatus')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    if ($scanResultID) {
        return SC-Connect -scResource scanResult -scResourceID $scanResultID -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
    }
    else {
        return SC-Connect -scResource scanResult -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
    }
}

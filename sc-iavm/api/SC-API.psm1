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


function Convert-UnixEpochTimestamp() {
    <# Make a Unix epoch'd timestamp human readable. #>
    param([int]$timestamp)
    return (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0).AddSeconds($timestamp)
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
    <# Attempt authentication with username/password
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
        [ValidateSet("auditFile", "config", "credential", "currentUser", "currentOrganization", "feed", "file/upload",
        "group", "ipInfo", "lce", "lce/eventTypes", "scanner", "organization", "passivescanner", "plugin", "pluginFamily",
        "query", "repository", "role", "scan", "policy", "scanResult", "zone", "status", "system", "ticket", "token",
        "reportDefinition", "scanResult/import", "analysis", "asset")]
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

    #$http_headers
    #break

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
    if ($name) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",name")}
    if ($description) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",description")}
    if ($status) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",status")}
    if ($policyTemplate) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",policyTemplate")}
    if ($policyProfileName) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",policyProfileName")}
    if ($creator) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",creator")}
    if ($tags) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",tags")}
    if ($createdTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",createdTime")}
    if ($modifiedTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",modifiedTime")}
    if ($context) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",context")}
    if ($generateXCCDFResults) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",generateXCCDFResults")}
    if ($auditFiles) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",auditFiles")}
    if ($preferences) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",preferences")}
    if ($targetGroup) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",targetGroup")}
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
    $dict = @{ "fields" = "id" }
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

    return SC-Connect -scResource repository -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
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
    $dict = @{ "fields" = "id" }
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
    return SC-Connect -scResource zone -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
}


function SC-Delete-Scan() {
    <#
        Deletes a scan item from the SecurityCenter, as specified by the scan's ID number.

        Parameter: scan_id: The ID of the scan to be deleted.

        Returns: Boolean $true upon success, otherwise Boolean $false.
    #>
    param(
        [ValidatePattern("^\d+$")]
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
        [switch]$getAllInfo,
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
    # Check if we're getting all info (set all switches to True)
    if ($getAllInfo) {
        $name = $description = $status = $ipList = $type = $policy = $plugin = $repository `
            = $zone = $dhcpTracking = $classifyMitigatedAge = $emailOnLaunch = $emailOnFinish `
            = $timeoutAction = $scanningVirtualHosts = $rolloverType = $createdTime = $modifiedTime `
            = $ownerGroup = $creator = $owner = $reports = $assets = $credentials = $numDependents `
            = $schedule = $policyPrefs = $maxScanTime = $true
    }
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
    if ($plugin) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",plugin")}
    if ($repository) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",repository")}
    if ($zone) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",zone")}
    if ($dhcpTracking) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",dhcpTracking")}
    if ($classifyMitigatedAge) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",classifyMitigatedAge")}
    if ($emailOnLaunch) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",emailOnLaunch")}
    if ($emailOnFinish) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",emailOnFinish")}
    if ($timeoutAction) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",timeoutAction")}
    if ($scanningVirtualHosts) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",scanningVirtualHosts")}
    if ($rolloverType) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",rolloverType")}
    if ($createdTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",createdTime")}
    if ($modifiedTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",modifiedTime")}
    if ($ownerGroup) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",ownerGroup")}
    if ($creator) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",creator")}
    if ($owner) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",owner")}
    if ($reports) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",reports")}
    if ($assets) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",assets")}
    if ($credentials) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",credentials")}
    if ($numDependents) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",numDependents")}
    if ($schedule) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",schedule")}
    if ($policyPrefs) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",policyPrefs")}
    if ($maxScanTime) {$dict.Set_Item("fields", $dict.Get_Item("fields") + ",maxScanTime")}
    
    if (!$id) {
        # ``$id`` is zero (true), so we want to get all scans.
        return SC-Connect -scResource scan -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
    }
    else {
        # ``$id`` has been set, so we want a specific scan's information
        return SC-Connect -scResource scan -scResourceID $id -scHTTPMethod GET -scQueryString (_SC-BuildQueryString $dict)
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
    SC-Connect -scResource scan -scResourceID $id -scHTTPMethod PATCH -scJSONInput $dict
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


function SC-Import-NessusResults() {
    <#
        An undocumented endpoint for importing results from an uploaded Nessus results file.

        Requires the addition of the "Content-Type:application/json" header.
    #>
    param(
        [string]$generatedFilename,
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
        return SC-Connect -scResource asset -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
    }
    else {
        # We only want a single asset list as identified by `$id`.
        return SC-Connect -scResourceID $id -scResource asset -scHTTPMethod GET -scQueryString (_SC-BuildQueryString -queryJSON $dict)
    }
}

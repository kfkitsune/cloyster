<#
    Contains critical functions used to communicate with the SecurityCenter.

    Critical functions:
     - SC-Authenticate
     - SC-Connect
     - SC-Logout

    Contains the following endpoints:
     - status
     - token
     - system
#>

#==> ``_70DBAC67`` - a unique string to mark this module's script variables
# The URI to the REST endpoint (e.g., "https://sc.contoso.com/rest/")
$scURI_70DBAC67 = ""
# The assigned token value from a system or token call
$scToken_70DBAC67 = $null
# A [Microsoft.PowerShell.Commands.WebRequestSession] from the Invoke-WebRequest call that logged into the SecurityCenter
$scSession_70DBAC67 = $null


function _debug-scVariables() {
    # Returns the current values of the persisted variables.
    return @{
        "uri" = $Script:scURI_70DBAC67;
        "token" = $Script:scToken_70DBAC67;
        "session"= $Script:scSession_70DBAC67
    }
}


function _SC-BuildQueryString {
    <#
        Build a valid query string from an incoming dictionary @{} of keys and values.

        Parameters:
          - queryDict: A dictionary (hash table) to be converted to a URI query string fragment.
              Values within queryDict are URLEncoded.

        Returns: A URLEncoded query string.

        $example = {
            "id" = 2;
            "filters" = "running"
        }
    #>
    param($queryDict);

    $reqStr = "?"
    foreach ($Local:item in $queryDict.GetEnumerator()) {
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
    #>
    param(
        [Parameter(Mandatory=$true, ParameterSetName="Password")]
          [System.Management.Automation.PSCredential]$credential = $null,
        [Parameter(Mandatory=$true, ParameterSetName="PKI")]
          [string]$pkiThumbprint = "",
        [Parameter(Mandatory=$true)]
        [ValidateScript({($_ -like "https://*") -and ($_ -notlike "https://*/")})]
          [string]$uri
    )
    $Script:scURI_70DBAC67 = $uri + "/rest/"
    
    if ($pkiThumbprint -ne "") {
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
    SC-Connect -scResource system -scHTTPMethod GET -pkiCertThumbprint $pkiCertThumbprint
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
          - scQueryStringDict: Optional. Used with HTTP GET requests. A dictionary @{} of Key-Value pairs to be translated
              to a query string to be appended to the REST endpoint URI.
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
            "analysis/download",
            "asset",
            "asset/import",
            "asset/-ID-/export",
            "asset/tags",
            "assetTemplate",
            "assetTemplate/categories",
            "auditFile",
            "auditFileTemplate",
            "auditFileTemplate/categories",
            "config",
            "credential",
            "currentOrganization",
            "currentUser",
            "feed",
            "file/clear",
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
            "reportDefinition/import",
            "reportDefinition/-ID-/export",
            "repository",
            "repository/-ID-/ipInfo",
            "role",
            "scan",
            "scanner",
            "scanResult",
            "scanResult/import",
            "scanResult/-ID-/stop",
            "scanResult/-ID-/pause",
            "scanResult/-ID-/resume",
            "scanResult/-ID-/download",
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
        $scQueryStringDict,
        $scJSONInput,
        $scAdditionalHeadersDict = @{},
        $scRawRequestPayload,
        [string]$pkiCertThumbprint = '-1'
    );
    <#
        Undocumented scResource values (among possibly a few others):
        - reportDefinition
        - scanResult/import
        - reportDefinition/<reportID>/export
    #>

    # Authentication must occur prior to using any other endpoints aside from ``token`` or ``system``
    if (($Script:scToken_70DBAC67 -eq $null) -and ($scResource -notin ("token", "system"))) {
        throw "Cannot access resource <$scResource> without authenticating; first use SC-Authenticate."
    }

    if ($scQueryStringDict) {
        $scQueryString = _SC-BuildQueryString -queryDict $scQueryStringDict
    }

    # Depth at 10 because the incoming dict might be more than 2 levels deep
    $json = $scJSONInput | ConvertTo-Json -Compress -Depth 10

    # If we have a token, then the X-SecurityCenter header must be set
    if ($Script:scToken_70DBAC67 -eq $null) { $http_headers=@{} }
    else {
        $http_headers = @{"X-SecurityCenter"= $Script:scToken_70DBAC67}
        # Do we need to add any additional headers?
        if ($scAdditionalHeadersDict.Count -gt 0) {
            $http_headers += $scAdditionalHeadersDict
        }
    }

    # Select endpoints operate in a manner such as /repository/{id}/ipInfo ... handle this
    # TODO: Is there a more elegant method of doing this?
    if ($scResource -like '*/-ID-/*') {
        # Writing to scResource causes a parameter validation issue (because of course it does down past the param() block... why though)
        if (!$scResourceID) {
            throw "Resource <$scResource> specified, but the ID of the item was not specified."
        }
        $true_resource = $scResource.Replace("-ID-", $scResourceID)
        Clear-Variable -Name scResourceID
    }
    else { $true_resource = $scResource }

    # Grab a local copy of the SC REST URI
    $scURI = $Script:scURI_70DBAC67

    # Send it.
    if ($scHTTPMethod -eq "POST") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $true_resource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $true_resource }
        
        if ($scResource -eq "file/upload") {
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $scRawRequestPayload -WebSession $Script:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
        elseif ($scResource -eq "token") {
            # Handle POST against ``/token`` resource (AKA, Get a token)
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $json -SessionVariable scSession -TimeoutSec 180 -Headers $http_headers);
        }
        else {
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $json -WebSession $Script:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
        
    }
    elseif ($scHTTPMethod -eq "PATCH") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $true_resource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $true_resource }

        $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method PATCH -Body $json -WebSession $Script:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
    }
    elseif ($scHTTPMethod -eq "GET") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $true_resource + '/' + $scResourceID + $scQueryString }
        else { $Local:tmpUri = $scURI + $true_resource + $scQueryString }
        
        # PKI: Handle GET against ``/system`` resource (AKA, Get a token)
        if ($scResource -eq "system") {
            if ($Script:scToken_70DBAC67) {
                # We already have a session, and we're trying to get something specific.
                $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method GET -WebSession $Script:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
            }
            else {
                # We are trying to get a token (so no session has been established yet)
                $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method GET -CertificateThumbprint $pkiCertThumbprint -SessionVariable scSession -TimeoutSec 180 -Headers $http_headers);
            }
        }
        else {
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method GET -WebSession $Script:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
    }
    elseif ($scHTTPMethod -eq "DELETE") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $true_resource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $true_resource }

        $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method DELETE -WebSession $Script:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
    }
    else {
        Write-Host($scHTTPMethod)
        # Catch-all for non-supported HTTP methods
        throw [System.NotImplementedException]
    }

    # Write-Host("Received: " + $scResponse)
    # Write-Host(">>RESPONSE CONTENTS<< ::: " + $scResponse.response)
    if (($scResource -in ("token", "system")) -and !$Script:scToken_70DBAC67) {
        # Store the token
        $Script:scToken_70DBAC67 = $scResponse.response.token;
        # Store the session
        $Script:scSession_70DBAC67 = $scSession
    }

    # Quick and dirty error checking, excluding resources that return in formats other than the standard JSON
    $specialReturnFormats = @(
        "policy/-ID-/export",
        "reportDefinition/-ID-/export",
        "asset/-ID-/export",
        "analysis/download",
        "scanResult/-ID-/download"
    )
    if ($scResource -notin $specialReturnFormats) {
        _SC-Connect-CheckError($scResponse)
    }
    
    # Return the response
    return $scResponse
}


function SC-Logout {
    try {
        SC-Connect -scResource token -scHTTPMethod DELETE
    }
    catch {
        Write-Debug("The SecurityCenter encountered an error when logging out; the error was:")
        Write-Debug($Error[0])
    }
    finally {
        # We're trying to log out here; either there will be an issue, or it will succeed. Clear token/session either way.
        Clear-Variable -Name scSession_70DBAC67 -Scope Script -ErrorAction SilentlyContinue
        Clear-Variable -Name scToken_70DBAC67 -Scope Script -ErrorAction SilentlyContinue
    }
}


function SC-Force-Logout {
    # Not so much a true 'logout' as a "clear the token and session variables, thus requiring a fresh login".
    Clear-Variable -Name scSession_70DBAC67 -Scope Script -ErrorAction SilentlyContinue
    Clear-Variable -Name scToken_70DBAC67 -Scope Script -ErrorAction SilentlyContinue
}


function SC-Get-Status() {
    $resp = SC-Connect -scResource status -scHTTPMethod GET
    return $resp.response
}

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

#==> ``_70DBAC67`` - a hopefully unique string to mark this module's global variables
# The URI to the REST endpoint (e.g., "https://sc.contoso.com/rest/")
$Global:scURI_70DBAC67 = ""
# The assigned token value from a system or token call
$Global:scToken_70DBAC67 = ""
# A [Microsoft.PowerShell.Commands.WebRequestSession] from the Invoke-WebRequest call that logged into the SecurityCenter
$Global:scSession_70DBAC67 = $null


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
            "asset",
            "asset/-ID-/export",
            "auditFile",
            "auditFileTemplate",
            "auditFileTemplate/categories",
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
        $scQueryStringDict,
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

    if ($scQueryStringDict) {
        $scQueryString = _SC-BuildQueryString -queryDict $scQueryStringDict
    }

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
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $scRawRequestPayload -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
        elseif ($scResource -eq "token") {
            # Handle POST against ``/token`` resource (AKA, Get a token)
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $json -SessionVariable scSession -TimeoutSec 180 -Headers $http_headers);
        }
        else {
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method POST -Body $json -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
        
    }
    elseif ($scHTTPMethod -eq "PATCH") {
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
            $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method GET -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
        }
    }
    elseif ($scHTTPMethod -eq "DELETE") {
        if ($scResourceID) { $Local:tmpUri = $scURI + $scResource + '/' + $scResourceID }
        else { $Local:tmpUri = $scURI + $scResource }

        $scResponse = (Invoke-RestMethod -Uri $Local:tmpUri -Method DELETE -WebSession $Global:scSession_70DBAC67 -TimeoutSec 180 -Headers $http_headers);
    }
    else {
        Write-Host($scHTTPMethod)
        # Catch-all for non-supported HTTP methods
        throw [System.NotImplementedException]
    }

    # Write-Host("Received: " + $scResponse)
    # Write-Host(">>RESPONSE CONTENTS<< ::: " + $scResponse.response)
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
    SC-Connect -scResource token -scHTTPMethod DELETE
    # We're trying to log out here; either there will be an issue, or it will succeed. Clear token either way.
    $Global:scToken_70DBAC67 = ""
}


function SC-Get-Status() {
    $resp = SC-Connect -scResource status -scHTTPMethod GET
    return $resp.response
}

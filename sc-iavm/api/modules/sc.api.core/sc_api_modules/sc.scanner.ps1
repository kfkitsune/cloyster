<#
    Functions for the /scanner endpoint. Really only useful for Administrator users, for the most part.
#>

function SC-Get-Scanner() {
    <#
        Returns information about all, or a single scanner.

        NOTE: This call will return all Scanners for an Administrator. For an Organization User, 
          it will only return agent-capable Scanners associated with that User's Organization.
    #>
    param(
        [ValidateScript({$_ -gt 0})]
        [int]$id,
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$agentCapable,
        <# Switches below only return if the user is an Admin user #>
        [switch]$ip,
        [switch]$port,
        [switch]$useProxy,
        [switch]$enabled,
        [switch]$verifyHost,
        [switch]$managePlugins,
        [switch]$authType,
        [switch]$cert,
        [switch]$username,
        [switch]$password,
        [switch]$version,
        [switch]$webVersion,
        [switch]$admin,
        [switch]$msp,
        [switch]$numScans,
        [switch]$numHosts,
        [switch]$numSessions,
        [switch]$numTCPSessions,
        [switch]$loadAvg,
        [switch]$uptime,
        [switch]$pluginSet,
        [switch]$loadedPluginSet,
        [switch]$serverUUID,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$zones,
        [switch]$nessusManagerOrgs
    )
    $fields = @{"fields" = ""}
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $fields.Set_Item("fields", ($fields.Get_Item("fields") + ",$key").TrimStart(','))
        }
    }

    if ($id -eq $null) {
        $resp = SC-Connect -scResource scanner -scHTTPMethod GET -scQueryStringDict $dict
    }
    else {
        # Only a specified scanner is being requested.
        $resp = SC-Connect -scResource scanner -scResourceID $id -scHTTPMethod GET -scQueryStringDict $dict
    }

    return $resp
}

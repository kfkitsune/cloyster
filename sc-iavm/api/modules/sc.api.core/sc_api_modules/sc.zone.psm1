<#
    Contains functions for interacting with scan zones.

    Contains the following endpoints:
      - zone
#>


function SC-Get-ScanZone() {
    <#
        https://docs.tenable.com/sccv/api/Scan-Zone.html
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
    return SC-Connect -scResource zone -scHTTPMethod GET -scQueryStringDict $dict
}

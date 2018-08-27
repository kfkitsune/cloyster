<#
    Contains functions for interacting with repositories.

    Contains the following endpoints:
      - repository
#>


function SC-Get-Repositories() {
    <#
        https://docs.tenable.com/sccv/api/Repository.html
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

    return SC-Connect -scResource repository -scHTTPMethod GET -scQueryStringDict $dict
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

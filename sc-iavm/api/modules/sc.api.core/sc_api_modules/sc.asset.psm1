<#
    Contains functions for interacting with asset lists

    Contains the following endpoints:
      - asset
      - asset/-ID-/export
#>


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
        return SC-Connect -scResource asset -scHTTPMethod GET -scQueryStringDict $dict
    }
    else {
        # We only want a single asset list as identified by `$id`.
        return SC-Connect -scResourceID $id -scResource asset -scHTTPMethod GET -scQueryStringDict $dict
    }
}


function SC-Export-AssetList() {
    <#
        Exports the Asset associated with ``assetListID`` as plain text XML.

        Parameters: assetListID: The asset list's ID to export.

        Returns: An XML copy of the asset list, suitable for importing to the SecurityCenter.

        API Reference: https://docs.tenable.com/sccv/api/Asset.html

        Endpoint: /asset/{id}/export
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$assetListID
    )
    return SC-Connect -scResource asset/-ID-/export -scResourceID $assetListID -scHTTPMethod GET
}


function SC-Patch-Asset-DNSList() {
    <# Modifies the asset identified by $id, changing only the passed in fields; this focuses on DNS List modification,
         but is by no means restricted to DNS-based asset lists. Consider this function an example. See API for full details. #>
    param(
        [Parameter(Mandatory=$true)]
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
    return SC-Connect -scResource asset -scResourceID $id -scHTTPMethod PATCH -scJSONInput $dict
}

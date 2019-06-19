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
          [int]$assetID,
        [switch]$id,
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
    $dict = @{ "fields" = "" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('assetID')) {
            $dict.Set_Item("fields", ($dict.Get_Item("fields") + ",$key").TrimStart(','))
        }
    }
    if ($dict['fields'] -eq "") { $dict.Remove('fields') }  # If no fields specified, clear for SC default fields
    
    if ($assetID) {
        # We only want a single asset list as identified by `$assetID`.
        return SC-Connect -scResource asset -scHTTPMethod GET -scQueryStringDict $dict -scResourceID $assetID
    }
    else {
        # Default case for when we want to retrieve all asset lists from the SecurityCenter
        return SC-Connect -scResource asset -scHTTPMethod GET -scQueryStringDict $dict
    }
}


function SC-Delete-AssetList() {
    <#
        Deletes the asset list associated with $id, depending on access and permissions
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$id
    )

    return SC-Connect -scResourceID $id -scResource asset -scHTTPMethod DELETE
}


function SC-Import-AssetList() {
    <#
        Imports an Asset specified by a previously uploaded, plain text XML file.

        NOTE: The filename field should contain the value of the same parameter passed back on */file/upload::POST*.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [string]$filename,
        [string]$name  # The new name of the asset list
    )
    $dict = @{ "name" = $name; "filename" = $filename; "tags" = ""; }
    
    return SC-Connect -scResource asset/import -scHTTPMethod POST -scJSONInput $dict -scAdditionalHeadersDict @{"Content-Type" = "application/json"}
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


function SC-Get-AssetTags() {
    <# Gets the full list of unique Asset tags #>
    return SC-Connect -scResource asset/tags -scHTTPMethod GET
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

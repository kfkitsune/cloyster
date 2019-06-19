<#
    assetTemplate endpoint

    https://docs.tenable.com/sccv/api/Asset-Template.html
#>

function SC-Get-AssetTemplate() {
    <#
        Retrieves information for all, or a specific, Asset Template.

        For a specific template, use `templateID`. `id` is the switch for returning that field
        in the returned data.
    #>
    param(
        [ValidateScript({$_ -gt -1})]
          [int]$templateID = -1,
        [switch]$id,
        [switch]$name,
        [switch]$description,
        [switch]$summary,
        [switch]$type,
        [switch]$category,
        [switch]$definition,
        [switch]$assetType,
        [switch]$enabled,
        [switch]$minUpgradeVersion,
        [switch]$templatePubTime,
        [switch]$templateModTime,
        [switch]$templateDefModTime,
        [switch]$definitionModTime,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$tags,
        [switch]$requirements,
        [switch]$assetTemplates,
        # Filter parameters
        [ValidateScript({$_ -gt 0})]
          [int]$categoryID,
        [string]$searchString,
        [ValidateScript({$_ -ge -1})]
          [int]$startOffset = 0,
        [ValidateScript({$_ -gt $startOffset})]
          [int]$endOffset
    )
    $dict = @{"fields"=""}
    # If we are filtering, add the filters...
    if ($categoryID) {$dict['categoryID'] = $categoryID}
    if ($searchString) {$dict['searchString'] = $searchString}
    if ($startOffset) {$dict['startOffset'] = $startOffset}
    if ($endOffset) {$dict['endOffset'] = $endOffset}
    
    # Load the switches into the fields...
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('templateID','categoryID','searchString','startOffset','endOffset')) {
            $dict.Set_Item("fields", ($dict.Get_Item("fields") + ",$key").TrimStart(','))
        }
    }

    if ($dict['fields'] -eq "") { $dict.Remove('fields') }  # If no fields specified, clear for SC default fields
    
    if ($templateID -ge 0) {
        return SC-Connect -scResource assetTemplate -scHTTPMethod GET -scQueryStringDict $dict -scResourceID $templateID
    }
    else {
        return SC-Connect -scResource assetTemplate -scHTTPMethod GET  -scQueryStringDict $dict
    }
}


function SC-Get-AssetTemplateCategories() {
    <# Gets the list of Asset Template categories #>
    return SC-Connect -scResource assetTemplate/categories -scHTTPMethod GET
}

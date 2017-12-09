<#
    Contains a function to export defined reports.

    Contains the following endpoints:
      - reportDefinition/-ID-/export
#>


function SC-Get-Reports() {
    <#
        Returns a list of reports from the SecurityCenter.

        Rest endpoint: /rest/reportDefinition

        Note: Undocumented endpoint, either in the SCCV or Cerberus variant of the API links
    #>
    param(
        [ValidateSet("usable","managable","usable,managable")]
          [string]$filter = "usable,managable",
        [switch]$name,
        [switch]$type,
        [switch]$ownerGroup,
        [switch]$owner,
        [switch]$schedule,
        [switch]$canManage,
        [switch]$canUse,
        [switch]$status
    )
    # Build the query dict
    $dict = @{
        "fields" = "id";
        "filter" = $filter
    }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        # Load the switch name into the `fields` (excluding non-switches)
        if ($key -notin @('filter')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }
    return SC-Connect -scResource reportDefinition -scHTTPMethod GET -scQueryStringDict $dict
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

<#
    Contains a function to export defined reports.

    Contains the following endpoints:
      - reportDefinition/-ID-/export
#>


function SC-Get-ReportDefinitions() {
    <#
        Returns a list of report definitions from the SecurityCenter.

        Rest endpoint: /rest/reportDefinition

        https://docs.tenable.com/sccv/api/Report-Definition.html
    #>
    param(
        [ValidateSet("usable","manageable","usable,manageable")]
          [string]$filter = "usable,manageable",
        [switch]$name,
        [switch]$description,
        [switch]$type,
        [switch]$ownerGroup,
        [switch]$owner,
        [switch]$schedule,
        [switch]$canManage,
        [switch]$canUse,
        [switch]$status,
        [switch]$emailTargets,
        [switch]$emailUsers
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


function SC-Delete-ReportDefinition() {
    <#
        Deletes a specified report definition, as identified by its ID number.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$id
    )

    return SC-Connect -scResource reportDefinition -scHTTPMethod DELETE -scResourceID $id
}


function SC-Edit-ReportDefinition() {
    <#
        Edits an existing report definition, changing only the passed parameters/fields.

        Not fully implemented (in this API, but there is a full reference in the API documentation).
        Currently only used here to template a report definition (AKA, unschedule/change to on demand), or to
        update the additional email recipients.

        https://docs.tenable.com/tenablesc/api/Report-Definition.htm
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$id,
        [ValidateSet("template")]
          [string]$newScheduleType = $null,
        [string]$newEmailTargets = $null
    )
    $dict = @{}
    if ($newScheduleType -eq "template") {
        $dict += @{"schedule" = @{"type" = "template"}}
    }
    if ($newEmailTargets) {
        $dict += @{"emailTargets" = $newEmailTargets}
    }

    # We must have something to change before we send (more validation)
    if ($dict.Count -eq 0) {
        throw "A report setting must be edited during a call to SC-Edit-Scan; no settings provided (`$dict is empty)"
    }

    return SC-Connect -scResource reportDefinition -scResourceID $id -scHTTPMethod PATCH -scJSONInput $dict
}


function SC-Export-ReportDefinition() {
    <#
        Exports the report definition for a specified report ID, optionally maintaining references to SecurityCenter specific objects,
        stripping them, or inserting placeholders.

        Rest endpoint: /rest/reportDefinition/<reportID>/export

        https://docs.tenable.com/sccv/api/Report-Definition.html

        Parameters:
          - reportID: The report ID of the report to be exported, as seen in the /#reports URI if visiting from the Web UI.
          - type: One of:
            > full: Maintains the references, if any, exactly as defined in the SecurityCenter. Suitable to import back into the same
                SecurityCenter without issues.
            > placeholder: Strips SecurityCenter specific references (repoID, assetIDs, etc.), and inserts placeholder information
                into the report template's definition.
            > cleansed: Fully strips references, leaving no placeholders.

        Returns: An XML file with the definition of the report as specified by ``reportID``, and obeying the ``type`` selection.
            Note: The returned information from the SC-Connect/Invoke-RestMethod is the raw XML data. It can be loaded into an [xml]
            object directly and used from there.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$reportID,
        [Parameter(Mandatory=$true)]
        [ValidateSet("full", "placeholders","cleansed")]
          [string]$type
    )
    $dict = @{ "exportType" = $type }

    return SC-Connect -scResource reportDefinition/-ID-/export -scResourceID $reportID -scHTTPMethod POST -scJSONInput $dict
}


function SC-Import-ReportDefinition() {
    <#
        Imports a report definition, using a previously uploaded report definition file (SC-Import-File).

        Parameters:
          - name: Optional String. The new name of the report. Otherwise, uses what is in the report definition.
          - filename: Required. The filename returned from the call to SC-Import-File
    #>
    param(
        [Parameter(Mandatory=$true)]
          [string]$filename,
        [string]$name
    )
    $dict = @{ "name" = $name; "filename" = $filename; }

    SC-Connect -scResource reportDefinition/import -scHTTPMethod POST -scJSONInput $dict -scAdditionalHeadersDict @{"Content-Type" = "application/json"}
}

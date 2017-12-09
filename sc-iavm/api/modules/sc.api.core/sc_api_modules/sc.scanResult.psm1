<#
    Functions for manipulating scan results, such as importing an already uploaded Nessus result file,
    or viewing the current status of scan results.

    Contains the following endpoints:
      - scanResult
      - scanResult/import
#>


function SC-Get-ScanResults() {
    <#
        Gets the list of Scan Results. The `progress` of a scan can be returned if a ``scanResultID`` is provided.

        Parameters:
          - scanResultID: The ID of a scan result entry. Required to return the `progress` of the scan. Optional. Int.
          - <switches>: See param() block below for information that can be returned.

        Returns: A list of all scans, or a single entry with the requested information
    #>
    param(
        [ValidateScript({$_ -ge 0})]
          [int]$scanResultID = $null,
        [ValidateSet("usable", "manageable", "usable,managable")]
          [string]$filterAccess = "usable,managable",
        [ValidateSet("running", "completed", "running,completed")]
          [string]$filterStatus = "running,completed",
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$initiator,
        [switch]$owner,
        [switch]$ownerGroup,
        [switch]$repository,
        [switch]$scan,
        [switch]$job,
        [switch]$details,
        [switch]$importStatus,
        [switch]$importStart,
        [switch]$importFinish,
        [switch]$importDuration,
        [switch]$downloadAvailable,
        [switch]$downloadFormat,
        [switch]$dataFormat,
        [switch]$resultType,
        [switch]$resultSource,
        [switch]$running,
        [switch]$errorDetails,
        [switch]$importErrorDetails,
        [switch]$totalIPs,
        [switch]$scannedIPs,
        [switch]$startTime,
        [switch]$finishTime,
        [switch]$scanDuration,
        [switch]$completedIPs,
        [switch]$completedChecks,
        [switch]$totalChecks,
        [switch]$progress
    )
    $filter = $filterAccess + ',' + $filterStatus

    $dict = @{ "fields" = "id";
               "filter" = $filter
    }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('scanResultID', 'filterAccess', 'filterStatus')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    if ($scanResultID) {
        return SC-Connect -scResource scanResult -scResourceID $scanResultID -scHTTPMethod GET -scQueryStringDict $dict
    }
    else {
        return SC-Connect -scResource scanResult -scHTTPMethod GET -scQueryStringDict $dict
    }
}


function SC-Import-NessusResults() {
    <#
        An undocumented endpoint for importing results from an uploaded Nessus results file.

        Requires the addition of the "Content-Type:application/json" header.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [string]$generatedFilename,
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$repositoryID = 7
    )
    # Build the query according to what was observed in-browser
    $dict = @{
        "classifyMitigatedAge" = 0;
        "context" = "";
        "createdTime" = 0;
        "description" = "";
        "dhcpTracking" = "true";
        "filename" = "$generatedFilename";
        "groups" = @();
        "modifiedTime" = 0;
        "name" = "";
        "repository" = @{"id" = $repositoryID};
        "rolloverType" = "template";
        "scanningVirtualHosts" = "false";
        "tags" = "";
        "timeoutAction" = "import";
    }
    # Send the import request
    return SC-Connect -scResource scanResult/import -scHTTPMethod POST -scJSONInput $dict -scAdditionalHeadersDict @{"Content-Type" = "application/json"}
}

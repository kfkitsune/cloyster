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
        [ValidateSet("usable", "manageable", "usable,manageable")]
          [string]$filterAccess = "usable,manageable",
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


function SC-Delete-ScanResult() {
    <#
        Deletes the scan result of a specified ID number.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$resultID
    )

    return SC-Connect -scResource scanResult -scResourceID $resultID -scHTTPMethod DELETE
}


function SC-Stop-ScanResult() {
    <#
        Stops a scan result (read: a running scan) as identified by the supplied scan ID.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$resultID
    )

    return SC-Connect -scResource scanResult/-ID-/stop -scResourceID $resultID -scHTTPMethod POST
}


function SC-Pause-ScanResult() {
    <#
        Pauses a scan result (read: a running scan) as identified by the supplied scan ID.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$resultID
    )

    return SC-Connect -scResource scanResult/-ID-/pause -scResourceID $resultID -scHTTPMethod POST
}


function SC-Resume-ScanResult() {
    <#
        Resumes a scan result (read: a running scan) as identified by the supplied scan ID.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$resultID
    )

    return SC-Connect -scResource scanResult/-ID-/resume -scResourceID $resultID -scHTTPMethod POST
}


function SC-Download-ScanResult() {
    <#
        Downloads a scan result (read: a running scan) as identified by the supplied scan ID.

        Note: Result will be binary (likely a ZIP), or ASCII (if it is .nessus).
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$resultID,
        [ValidateSet("v2","scap1_2")]
          [string]$downloadType = "v2"
    )
    $dict = @{"downloadType" = $downloadType}
    return SC-Connect -scResource scanResult/-ID-/download -scResourceID $resultID -scJSONInput $dict -scHTTPMethod POST -scAdditionalHeadersDict @{"Content-Type" = "application/json"}
}


function SC-Import-NessusResults() {
    <#
        Imports results from an uploaded Nessus results file.
        
        https://docs.tenable.com/sccv/api/Scan-Result.html#ScanResultRESTReference-/scanResult/import

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

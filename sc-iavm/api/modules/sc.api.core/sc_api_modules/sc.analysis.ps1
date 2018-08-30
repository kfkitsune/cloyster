<#

#>

function _get_sclog_basenames() {
    <#
        Returns the basenames for all scLogs in the SecurityCenter

        Returns: An iterable containing the basenames present in the logs.
    #>
    $dict = @{
        "fields" = "scLogs"
    }
    $resp = SC-Connect -scResource system -scHTTPMethod GET -scQueryStringDict $dict
    return $resp.response.scLogs.basenames
}


function SC-Get-SystemLogs() {
    <#
        Retrieves log information from the SecurityCenter.

        Parameters: Duplicates some parameters from ``SC-Download-SystemLogs()``.
    #>
    param(
        [ValidatePattern("^\d+$")]
          [int]$startOffset = 0,
        [ValidatePattern("^\d+$")]
        [ValidateScript({$_ -gt $startOffset})]
          [int]$endOffset = 250,
        [ValidateSet("INFO", "WARN", "CRITICAL", "ALL")]
          $severity = "ALL",
        [ValidatePattern("^(\d+|all)$")]
          $date = "all",
        [string]$keywords = $null,
        [int]$orgID = $null
    )
    # More parameter validation
    if ($date -ne "all") {
        $sclog_basenames = _get_sclog_basenames
        Write-Host($sclog_basenames)
        Write-Host($date)
        if ($date -notin $sclog_basenames) {
            throw "Invalid date parameter; not a valid scLog basename"
        }
    }

    $dict = @{
        #"status" = -1
        "type" = "scLog";
        "sourceType" = "scLog";
        "sortField" = "date";
        "sortDir" = "desc";
        "date" = $date
        "query" = @{
            "startOffset" = $startOffset;
            "endOffset" = $endOffset;
            "filters" = @();
            #"tool" = "scLog";
            #"type" = "scLog";
            #"scLogTool" = "scLog";
        }
    }

    if ($keywords) {
        $dict.query.filters += @{
            "filterName" = "keywords";
            "operator" = '=';
            "value" = $keywords;
        }
    }

    if ($severity -ne "ALL") {
        $sev_id = 0
        if ($severity -eq "WARNING") { $sev_id = 1 }
        elseif ($severity -eq "CRITICAL") { $sev_id = 2 }
        $dict.query.filters += @{
            "filterName" = "severity";
            "operator" = '=';
            "value" = @{ "id" = $sev_id }
        }
    }

    if ($orgID) {
        $dict.query.filters += @{
            "filterName" = "organization";
            "value" = @{
                "id" = $orgID
            }
        }
    }
    return (SC-Connect -scResource analysis -scHTTPMethod POST -scJSONInput $dict).response
}


function SC-Download-SystemLogs() {
    <#
        Downloads in plaintext the contents of a SecurityCenter's System Logs.

        Parameters:
            startOffset: The starting offset to begin retrieving records at. Default: 0.
            endOffset: The ending offset for record retrieval. Default: 250.
            severity: The severity of log item to retrieve. Options are INFO, WANR, CRITICAL, ALL.
                ALL retrieves all severity levels, and is the Default.
            date: The log date to retrieve. Values are either an integer in the format of YYYYMM (e.g., 201801), or "all".
                Default: all.
            username: Optional; if specified, retrieves events recorded under a specific user account.
            keywords: Optional; keywords separated by " ", "\t", "\n", or "\r" (eg. "Authentication User")
            orgID: Admin only option; if defined, the organization ID to retrieve logs for. Default is $null. Optional.

        Returns: A CSV formatted response.
        
        Example of a log line:
        "Thu, 30 Aug 2018 12:34:56 +0000","system","riskRules","INFO","Applying Recast and Accept Risk Rules successful for Repository #1."
    #>
    param(
        [ValidatePattern("^\d+$")]
          $startOffset = 0,
        [ValidatePattern("^\d+$")]
        [ValidateScript({$_ -gt $startOffset})]
          $endOffset = 250,
        [ValidateSet("INFO", "WARN", "CRITICAL", "ALL")]
          $severity = "ALL",
        [ValidatePattern("^(\d+|all)$")]
          $date = "all",
        $keywords = $null,
        $orgID = $null
    )
    # More parameter validation
    if ($date -ne "all") {
        $sclog_basenames = _get_sclog_basenames
        if ($date -notin $sclog_basenames) {
            throw "Invalid date parameter; not a valid scLog basename"
        }
    }

    $dict = @{
        "type" = "scLog";
        "date" = $date
        "query" = @{
            "startOffset" = $startOffset;
            "endOffset" = $endOffset;
        }
    }

    if ($severity -ne "ALL") { $dict.query['severity'] = $severity }
    if ($keywords) { $dict.query['keywords'] = $keywords }
    if ($orgID) { $dict.query['orgID'] = $orgID }

    SC-Connect -scResource analysis/download -scHTTPMethod POST -scJSONInput $dict
}


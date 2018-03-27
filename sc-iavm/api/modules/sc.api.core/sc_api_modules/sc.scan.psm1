<#
    Functions for manipulating scans.

    Contains the following endpoints:
      - scan
#>


function SC-Delete-Scan() {
    <#
        Deletes a scan item from the SecurityCenter, as specified by the scan's ID number.

        Parameter: scan_id: The ID of the scan to be deleted.

        Returns: Boolean $true upon success, otherwise Boolean $false.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$scan_id
    )
    $resp = SC-Connect -scResource scan -scResourceID $scan_id -scHTTPMethod DELETE

    return !$resp.error_code
}


function SC-Get-ScanInfo() {
    <#
        Retrieves information about single or multiple scans. ``id``, if set, will return
          information specifically about the scan with that ID number.

        Parameters:
          - id: Integer; If specified, only retrieve information about the scan with the ID number given.
              otherwise, retrieve all scans' info.
          - filter: Only retrieve usable, manageable, or both usable and manageable scans. Defaults
              to both usable and manageable scans returned.
          - getAllInfo: Switch; if specified, sets all switches to True to return all info
    #>
    param (
        [ValidatePattern("^\d+$")]
          [int]$id = 0,
        [ValidateSet("usable","manageable","usable,manageable")]
          [string]$filter = "usable,manageable",
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$ipList,
        [switch]$type,
        [switch]$policy,
        [switch]$plugin,
        [switch]$repository,
        [switch]$zone,
        [switch]$dhcpTracking,
        [switch]$classifyMitigatedAge,
        [switch]$emailOnLaunch,
        [switch]$emailOnFinish,
        [switch]$timeoutAction,
        [switch]$scanningVirtualHosts,
        [switch]$rolloverType,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$ownerGroup,
        [switch]$creator,
        [switch]$owner,
        [switch]$reports,
        [switch]$assets,
        [switch]$credentials,
        [switch]$numDependents,
        [switch]$schedule,
        [switch]$policyPrefs,
        [switch]$maxScanTime
    )
    # Build the query dict
    $dict = @{
        "fields" = "id";
        "filter" = $filter
    }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        # Load the switch name into the `fields` (excluding non-switches)
        if ($key -notin @('id','filter')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }
    
    if (!$id) {
        # ``$id`` is zero (true), so we want to get all scans.
        return SC-Connect -scResource scan -scHTTPMethod GET -scQueryStringDict $dict
    }
    else {
        # ``$id`` has been set, so we want a specific scan's information
        return SC-Connect -scResource scan -scResourceID $id -scHTTPMethod GET -scQueryStringDict $dict
    }
}


function SC-Create-Scan() {
    <#
        Adds a new scan to the SecurityCenter.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [string]$name,
        [Parameter(Mandatory=$true,ParameterSetName="PluginType")]
        [Parameter(Mandatory=$true,ParameterSetName="PolicyType")]
        [ValidateSet("plugin", "policy")]
          [string]$type,
        [Parameter(Mandatory=$true,ParameterSetName="PluginType")]
        [ValidateScript({$_ -gt 0})]
          [int]$pluginID,  # Only used if ``$type`` is ``plugin``
        [Parameter(Mandatory=$true,ParameterSetName="PolicyType")]
        [ValidateScript({$_ -gt 0})]
          [int]$policyID,  # Only used if ``$type`` is ``policy``
        [string]$description = "",
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$repositoryID,
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$scanZoneID = 0,
        [ValidateSet("true", "false")]
          [string]$dhcpTracking = "false",
        [ValidateSet(0,1,2,3,4,5,6,30,60,90,365)]
          [int]$classifyMitigatedAge = 0,
        $reports = @(),  # Not yet implemented
        [ValidateScript({$_ -gt 0})]
          [int[]]$assetListIDs = @(),
        [ValidateScript({$_ -gt 0})]
          [int[]]$credentialIDs = @(),
        [ValidateSet("true", "false")]
          [string]$emailOnLaunch = "false",
        [ValidateSet("true", "false")]
          [string]$emailOnFinish = "false",
        [ValidateSet("discard", "import", "rollover")]
          [string]$timeoutAction = "import",
        [ValidateSet("nextDay", "template")]
          [string]$rolloverType = "template",
        [ValidateSet("true", "false")]
          [string]$scanningVirtualHosts = "false",
        [ValidateScript({$_ -gt 0})]  # In hours
          [int]$maxScanTime = 3600,
        [string]$ipList = "",  # Can be a CSV IP and/or FQDN list (e.g., "1.1.1.1,box.contoso.com")
        [ValidateSet("template", "dependent", "ical", "never", "rollover")]
          [string]$schedule = "template",
        # If ``type`` is ``ical``, the following are required:
        [DateTime]$startDateTime,
        [ValidateSet("ONCE","DAILY","WEEKLY","MONTHLY")]
          [string]$repeatRuleFreq = "ONCE",
        [ValidateScript({($_ -gt 0) -and ($_ -le 20)})]
          [string]$repeatRuleInterval = 1,
        [ValidateSet("SU","MO","TU","WE","TH","FR","SA")]
          [string[]]$repeatRuleByDay = "MO",
        [int]$repeatRuleNthDayOfTheWeek = -1,  # e.g., first Monday of every Month (1MO), Tuesday (1TU), etc.
        [int]$repeatRuleDayOfTheMonth = -1,  # e.g., repeat every month on day N
        # If ``type`` is ``dependent`` the following is required:
        [ValidateScript({$_ -gt 0})]
          [int]$dependentScanID = $null
    )
    # Begin loading the parameters into the POST storage
    $dict = @{}

    $dict += @{ "name" = $name }
    $dict += @{ "type" = $type }
    if ($type -eq "plugin") {
        if (!$pluginID) { throw "Plugin type is selected, but no pluginID specified." }
        $dict += @{ "pluginID" = $pluginID }
    }
    elseif ($type -eq "policy") {
        if (!$policyID) { throw "Policy type is selected, but no policyID specified." }
        $dict += @{ "policy" = @{ "id" = $policyID } }
    }
    $dict += @{ "description" = $description }
    $dict += @{ "repository" = @{ "id" = $repositoryID } }
    $dict += @{ "zone" = @{ "id" = $scanZoneID } }
    $dict += @{ "dhcpTracking" = $dhcpTracking }
    $dict += @{ "classifyMitigatedAge" = $classifyMitigatedAge }
    # Generate the schedule component
    if (($schedule -eq "ical") -or ($schedule -eq "dependent")) {
        $dict += (_GenerateScanScheduleJSONComponent -schedule $schedule -startDateTime $startDateTime -repeatRuleFreq $repeatRuleFreq -repeatRuleInterval $repeatRuleInterval `
            -repeatRuleByDay $repeatRuleByDay -repeatRuleNthDayOfTheWeek $repeatRuleNthDayOfTheWeek `
            -repeatRuleDayOfTheMonth $repeatRuleDayOfTheMonth -dependentScanID $dependentScanID
        )
    }
    else {
        $dict += @{ "schedule" = $schedule }
    }
    $dict += @{ "reports" = @() }
    # Generate the Assets ID block
    if ($assetListIDs) {
        $assets = @()
        foreach ($asset in $assetListIDs) {
            $assets += @{ "id" = $asset }
        }
        $dict += @{ "assets" = $assets }
    } else { $dict += @{ "assets" = @() } }
    # Generate the Credential ID block
    if ($credentialIDs) {
        $creds = @()
        foreach ($id in $credentialIDs) {
            $creds += @{ "id" = $id }
        }
        $dict += @{ "credentials" = $creds }
    } else { $dict += @{ "credentials" = @() } }
    $dict += @{ "emailOnLaunch" = $emailOnLaunch }
    $dict += @{ "emailOnFinish" = $emailOnFinish }
    $dict += @{ "timeoutAction" = $timeoutAction }
    $dict += @{ "scanningVirtualHosts" = $scanningVirtualHosts }
    $dict += @{ "rolloverType" = $rolloverType }
    $dict += @{ "ipList" = $ipList }
    $dict += @{ "maxScanTime" = $maxScanTime }

    # TODO: Finish this function. It's not yet ready (or tested).
    return $dict
}


function _GenerateScanScheduleJSONComponent() {
    <#
        Constructs the ``schedule`` object for a scan request

        Monthly scans are special and follow the rules below:
          - To conduct a scan on the Nth-day of the week, set ``repeatRuleNthDayOfTheWeek`` to the week-number (1-4), and
              ``repeatRuleByDay`` to the weekday on which the scan should run.
          - To conduct a scan every Nth-day of the month (e.g., every first of the month), set ``repeatRuleDayOfTheMonth``
              to the day on which the scan should be run monthly.

        Parameters:
          - schedule: The schedule type. This function processes `ical` and `dependent` types
          - startDateTime: A DateTime object. Rounds **up** to the nearest 30 minute interval (respecting the SC UI's time bounds).
          - repeatRuleFreq: How often should the scan run? Defaults to Once; Options are (Once, Daily, Weekly, Monthly)
          - repeatRuleInterval: On frequencies other than `Once`, how often should this scan execute. Unit of time is
              indicated in the same units as the Frequency. E.g., every 2 days, every 2 weeks, every 2 months.
          - repeatRuleByDay: A [String] array of days on which to run scans on the 'DAILY' Frequency. Defaults to MO = Monday.
          - repeatRuleNthDayOfTheWeek: On the Monthly frequency, specifies the week-number on which the scan executes. E.g,
              run the scan on the Fourth Friday of each month. Must be specified with ``repeatRuleByDay`` (one element)
          - repeatRuleDayOfTheMonth: On the Monthly frequency, specifies on which day the scan is to run, such as the first
              of every month.
          - dependentScanID: If ``schedule`` is of type `dependent`, the dependent scan ID to chain this schedule object to.
    #>
    param(
        [ValidateSet("ical", "dependent")]
          [string]$schedule,
        [DateTime]$startDateTime,
        [ValidateSet("ONCE", "DAILY", "WEEKLY", "MONTHLY")]
          [string]$repeatRuleFreq = "ONCE",
        [ValidateScript({($_ -gt 0) -and ($_ -le 20)})]
          [string]$repeatRuleInterval = 1,
        [ValidateSet("SU", "MO", "TU", "WE", "TH", "FR", "SA")]
          [string[]]$repeatRuleByDay = "MO",
        [ValidateSet(-1, 1, 2, 3, 4)]
        [int]$repeatRuleNthDayOfTheWeek = -1,  # e.g., first Monday of every Month (1MO), Tuesday (1TU), etc.
        [int]$repeatRuleDayOfTheMonth = -1,  # e.g., repeat every month on day N
        [ValidateScript({$_ -ge -1})]
          [int]$dependentScanID = -1
    )
    if ($schedule -eq "ical") {
        # Process the ``repeatRule`` component of the ``schedule`` object...
        if ($repeatRuleFreq -eq "MONTHLY") {
            #Write-Host($repeatRuleDayOfTheWeek -eq -1)
            if ( ($repeatRuleNthDayOfTheWeek -ne -1) -and ($repeatRuleDayOfTheMonth -ne -1) ) {
                throw "Cannot determine correct repeat rule (repeatRuleDayOfTheWeek and repeatRuleDayOfTheMonth are both set)"
            }
            elseif ( ($repeatRuleNthDayOfTheWeek -eq -1) -and ($repeatRuleDayOfTheMonth -ne -1) ) {
                $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval + ";BYMONTHDAY=" + $repeatRuleDayOfTheMonth
            }
            elseif ( ($repeatRuleNthDayOfTheWeek -ne -1) -and ($repeatRuleDayOfTheMonth -eq -1) ) {
                $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval + ";BYDAY=" + $repeatRuleNthDayOfTheWeek + $repeatRuleByDay[0]
            }
        }
        elseif ($repeatRuleFreq -eq "WEEKLY") {
            $_byDay = @()
            foreach ($day in $repeatRuleFreq) {
                # Join any days into a single string array
                $_byDay += $day
            }
            $_byDay = $_byDay | Get-Unique
            $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval + ";BYDAY=" + $_byDay
        }
        elseif ($repeatRuleFreq -eq "DAILY") {
            $_repeatRule = "FREQ=" + $repeatRuleFreq + ";INTERVAL=" + $repeatRuleInterval
        }
        else {
            # One-time scan, so no repeatRule needed
            $_repeatRule = ""
        }

        # Process the date... Temp timezone until I figure out how I want to expand this...
        if (($startDateTime.Minute % 30) -ne 0) {
            # Round upwards to the nearest 30 minutes (respect the UI interface's limitations)
            $diff = (30 - ($startDateTime.Minute % 30))
            $startDateTime = $startDateTime.AddMinutes($diff)
        }
        $_tzone = "America/New_York"
        $_start = "TZID=" + $_tzone + ":" + (Get-Date $startDateTime -Format yyyyMMddTHHmm00)
    }
    elseif ($schedule -eq "dependent") {
        $_repeatRule = "FREQ=undefined;INTERVAL=1"
        $_date = (Get-Date).AddDays(2)
        $_start = (Get-Date $_date -Format MM/dd/yyyy)
    }
    else { throw [System.NotImplementedException] }  # We should **not** get to this block.
    
    # Construct/return the ``schedule`` object
    $_schedule = @{
            "start" = $_start;
            "repeatRule" = $_repeatRule;
            "type" = $schedule;
    }
    if ($schedule -eq "dependent") {
        if ($dependentScanID -ne -1) {
            $_schedule += @{ "dependentID" = $dependentScanID }
        }
        else {
            # Dependent scans **must** have the dependentScanID set
            throw "Cannot schedule a Dependent-type scan when `$dependentScanID is not set."
        }
    }

    return @{ 
        "schedule" = $_schedule
    }
}


function SC-Edit-Scan() {
    <#
        Edit the scan with an ID ``id``, changing only passed in fields. Not fully implemented from the API reference.
        API Reference: https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Scan.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$id,
        [ValidateScript({$_ -gt 0})]
          [int]$newPolicyID = $null,
        [ValidateScript({($_.Length -le 1024) -and ($_.Length -ge 1)})]
          [string]$newName = $null,
        [string]$newDescription = $null,
        [ValidateScript({$_ -gt 0})]
          [int]$newImportRepositoryID = $null,
        [ValidateScript({$_ -gt 0})]
          [int]$newScanZoneID = $null,
        [ValidateSet("true","false")]
          [string]$newEmailOnLaunch = $null,
        [ValidateSet("true","false")]
          [string]$newEmailOnFinish = $null,
        [ValidateSet("discard", "import", "rollover")]
          [string]$newTimeoutAction = $null,
        [ValidateSet("true","false")]
          [string]$newScanningVirtualHosts = $null,
        [ValidateSet("nextDay", "template")]
          [string]$newRolloverType = $null,
        [ValidateScript({$_ -gt 0})]  # In hours
          [int]$newMaxScanTime = $null,
        [ValidateSet("true","false")]
          [string]$newDHCPTracking = $null,
        [ValidateSet(0,1,2,3,4,5,6,30,60,90,365)]
          [int]$newClassifyMitigatedAge = $null,
        [Parameter(ParameterSetName="credentials")]
        [ValidateScript({$_ -gt 0})]
          [int[]]$newCredentialIDs = $null,
        [Parameter(ParameterSetName="credentials")]
          [switch]$clearCredentials,
        [string]$newIPList = $null,
        [Parameter(ParameterSetName="assets")]
        [ValidateScript({$_ -gt 0})]
          [int[]]$newAssets = $null,
        [Parameter(ParameterSetName="assets")]
        [switch]$clearAssets
        # NYI: schedule, reports
    )
    $dict = @{}
    if ($newPolicyID) { $dict += @{ "policy" = @{"id" = $newPolicyID} } }
    if ($newName) { $dict += @{ "name" = $newName } }
    if ($newDescription) { $dict += @{ "description" = $newDescription } }
    if ($newImportRepositoryID) { $dict += @{ "repository" = @{"id" = $newImportRepositoryID} } }
    if ($newScanZoneID) { $dict += @{ "zone" = @{"id" = $newScanZoneID} } }
    if ($newEmailOnLaunch) { $dict += @{ "emailOnLaunch" = $newEmailOnLaunch } }
    if ($newEmailOnFinish) { $dict += @{ "emailOnFinish" = $newTimeoutAction } }
    if ($newTimeoutAction) { $dict += @{ "timeoutAction" = $newDescription } }
    if ($newScanningVirtualHosts) { $dict += @{ "scanningVirtualHosts" = $newScanningVirtualHosts } }
    if ($newRolloverType) { $dict += @{ "rolloverType" = $newRolloverType } }
    if ($newIPList) { $dict += @{ "ipList" = $newIPList } }
    if ($newMaxScanTime) { $dict += @{ "maxScanTime" = $newMaxScanTime } }
    if ($newDHCPTracking) { $dict += @{ "dhcpTracking" = $newDHCPTracking } }
    if ($newClassifyMitigatedAge) { $dict += @{ "classifyMitigatedAge" = $newClassifyMitigatedAge } }
    if ($newCredentialIDs) {  # Build the credentials subset
        $creds = @()
        foreach ($credentialID in $newCredentialIDs) {
            $creds += @{ "id" = $credentialID }
        }
        $dict += @{ "credentials" = $creds }
    }
    if ($clearCredentials) { $dict += @{ "credentials" = @() } }
    if ($newAssets) { # Build the assets subset
        $assets = @()
        foreach ($assetID in $newAssets) {
            $assets += @{ "id" = $assetID }
        }
        $dict += @{ "assets" = $assets }
    }
    if ($clearAssets) { $dict += @{ "assets" = @() } }

    # We must have something to change before we send (more validation)
    if ($dict.Count -eq 0) {
        throw "A scan setting must be edited during a call to SC-Edit-Scan; no settings provided (`$dict is empty)"
    }

    #Write-Host ($dict | ConvertTo-Json -Depth 10 -Compress)
    return SC-Connect -scResource scan -scResourceID $id -scHTTPMethod PATCH -scJSONInput $dict
}


function SC-Get-RolloverScans() {
    <# Find any rollover scans #>
    $resp = SC-Get-ScanInfo -filter manageable -name -schedule -ownerGroup -owner -createdTime
    return $resp.response.manageable | Where-Object { $_.schedule.type -eq "rollover" }
}


function SC-Purge-RolloverScans() {
    <# Purge any and all rollover scans that are detected in the SecurityCenter #>
    $rollover_scans = SC-Get-RolloverScans
    $curr_count = 0
    foreach ($scan in $rollover_scans) {
        $progress = ($curr_count++ / $rollover_scans.Count) * 100
        Write-Progress -Activity "Purging all Rollover scans" -Status ("Percent complete: " + $progress + "%") -PercentComplete $progress
        Write-Host ("Purging: {id = " + $scan.id + "; name = `"" + $scan.name + "`"; owner = `"" + $scan.owner.username + "`"}")
        SC-Delete-Scan -scan_id $scan.id | Out-Null
    }
}

# The prefix for the domain controllers to check (e.g., "NYC" for NYC001, NYC002, NYC003)
$target_dc_prefix_regex = "^(NYC|SJC|JPN).*"
# The AD SearchBase (i.e., OU) to constrain getting objects from (e.g., OU=Users,DC=contoso,DC=com)
$target_ad_searchbase = "OU=Main,DC=contoso,DC=com"


# Module imports
try {  ### Begin module import block ###
    $location_of_modules = ";$env:USERPROFILE\Documents\AuthScripts\modules"
    if ($env:PSModulePath -notlike ('*' + $location_of_modules + '*')) {
        $env:PSModulePath += $location_of_modules
    }
    Import-Module KFK-CommonFunctions -Function ("Convert-FileTimeToDateTime", "Convert-DateTimeToFileTime", "Get-FileName") -ErrorAction Stop
    Import-Module -ErrorAction Stop ActiveDirectory
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
} ### End module import block ###


# Get a listing of all domain controllers for the current domain
$ad_information = Get-ADDomain
$target_domain_controllers = $ad_information.ReplicaDirectoryServers -cmatch $target_dc_prefix_regex
$date_now = Get-Date

Write-Host -ForegroundColor Cyan "Do you want to retrieve last logon dates for:"
Write-Host -ForegroundColor Cyan "[1] User objects"
Write-Host -ForegroundColor Cyan "[2] Computer objects"
$input = [int](Read-Host -Prompt "Enter [1] or [2]; other values assume user; <Ctrl+C> to exit")
if ($input -eq 1) {
    $object_type = "user"
}
elseif ($input -eq 2) {
    $object_type = "computer"
}
else {
    Write-Host -ForegroundColor Yellow "Invalid input; assuming user objects"
    $object_type = "user"
}

# Initialize the AD query storage location...
$datastore = [System.Collections.Generic.List[System.Object]]::new(1000000)

# Get all targeted objects from each domain controller
foreach($dc in $target_domain_controllers) {
    # Build out the AD searcher [Ref: https://stackoverflow.com/a/60419117]
    # Why manual? Because this takes F O R E V E R when using the cmdlets
    $ad_searcher = [adsisearcher]::new([adsi]"LDAP://$dc/$target_ad_searchbase", "(objectCategory=$object_type)")
    $ad_searcher.PropertiesToLoad.Add("name") > $null
    $ad_searcher.PropertiesToLoad.Add("samaccountname") > $null
    $ad_searcher.PropertiesToLoad.Add("distinguishedName") > $null
    $ad_searcher.PropertiesToLoad.Add("userAccountControl") > $null  # Ref: https://stackoverflow.com/a/47099079
    $ad_searcher.PropertiesToLoad.Add("lastlogon") > $null
    $ad_searcher.PropertiesToLoad.Add("lastlogontimestamp") > $null
    $ad_searcher.PropertiesToLoad.Add("pwdLastSet") > $null
    $ad_searcher.PropertiesToLoad.Add("objectClass") > $null
    $ad_searcher.PageSize = 1000

    Write-Host -ForegroundColor Gray "Retrieving data from DC [$dc]..."
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $results = $ad_searcher.FindAll()
    $results | Measure-Object > $null  # Because it wants to die mid-processing and/or not retrieve data until actual use?
    Write-Host -ForegroundColor DarkGray ("[DEBUG] Data retrieval took "+ $stopwatch.Elapsed.TotalSeconds + " seconds; " + $results.Count + " objects found")

    $count = 0; $activity = "Storing data [$dc]"
    foreach($obj in $results) {
        if ($stopwatch.Elapsed.TotalMilliseconds -ge 500) {
            Write-Progress -id 0 -Activity $activity -CurrentOperation "$count records processed" -PercentComplete (100 * ($count / $results.Count))
            $stopwatch.Restart()
        }

        if ($obj.Properties.objectclass -contains "contact") {
            continue  # Skip contact AD Objects...
        }

        # Load the resulting information into the data store
        $data = [PSCustomObject]@{
            'name' = $obj.Properties['name'][0].ToString()
            'samaccountname' = $obj.Properties['samaccountname'][0].ToString()
            'distinguishedName' = $obj.Properties['distinguishedname'][0].ToString()
            'enabled' = ($obj.Properties['useraccountcontrol'].Item(0) -band 2) -ne 2
            'lastLogon' = $obj.Properties['lastlogon'][0]
            'pwdLastSet' = $obj.Properties['pwdLastSet'][0]
            'lastLogonTimestamp' = $obj.Properties['lastlogontimestamp'][0]
            '_domain_controller' = $dc
        }
        $datastore.Add($data)
        $count += 1
    }
    $ad_searcher.Dispose()
    Write-Progress -id 0 -complete -Activity $activity
}

# Combine the results from each DC down to a single collection
Write-Host -ForegroundColor Gray "[INFO] Grouping records, this might take a moment..."
$grouped_results = $datastore | Group-Object -Property samaccountname


$datastore = [System.Collections.Generic.List[System.Object]]::new(1000000);
$count = 0; $progress_activity = "Processing last logon dates"; $stopwatch.Reset(); $stopwatch.Start()
foreach($result in $grouped_results) {
    if ($stopwatch.Elapsed.TotalMilliseconds -ge 500) {
        Write-Progress -id 0 -Activity $progress_activity -CurrentOperation "$count records processed" -PercentComplete (100 * ($count / $grouped_results.Count))
        $stopwatch.Restart()
    }

    # Ignore service accounts or other things to avoid
    if($result.Group[0].DistinguishedName -notlike "*,OU=MISCELLANEOUS,*") {

    }

    $lastlogon_datetimes = $result.Group | ForEach-Object {Convert-FileTimeToDateTime($_.lastLogon)}
    if ($lastlogon_datetimes) {
        $latest_logon_date = ($lastlogon_datetimes | Sort-Object -Descending)[0]
    }
    $lastlogontimestamp_datetimes = $result.Group | ForEach-Object {Convert-FileTimeToDateTime($_.lastLogonTimestamp)}
    if ($lastlogontimestamp_datetimes) {
        $latest_lastlogontimestamp_date = ($lastlogontimestamp_datetimes | Sort-Object -Descending)[0]
    }
    $pwdlastset_datetimes = $result.Group | ForEach-Object {Convert-FileTimeToDateTime($_.pwdLastSet)}
    if ($pwdlastset_datetimes) {
        $latest_pwdlastset_date = ($pwdlastset_datetimes | Sort-Object -Descending)[0]
    }

    $data = [PSCustomObject]@{
        "Name" = $result.Group[0].name
        "SamAccountName" = $result.Group[0].samaccountname
        "Enabled" = $result.Group[0].enabled
        "Last Login" = $latest_logon_date
        "Days Since Last Login" = (New-TimeSpan -Start $latest_logon_date -End $date_now).Days
        "Latest Last Logon Timestamp (Replicates)" = $latest_lastlogontimestamp_date
        "Days Since Latest Last Logon Timestamp" = (New-TimeSpan -Start $latest_lastlogontimestamp_date -End $date_now).Days
        "Account Password Last Set" = $latest_pwdlastset_date
        "Days Since Account Password Last Set" = (New-TimeSpan -Start $latest_pwdlastset_date -End $date_now).Days
        "All Available LastLogon Dates" = $lastlogon_datetimes -join " | "
        "All Available LastLogonTimestamp Dates" = $lastlogontimestamp_datetimes -join " | "
        "All Available PwdLastSet Dates" = $pwdlastset_datetimes -join " | "
        "distinguishedName" = $result.Group[0].distinguishedName
    }
    $datastore.Add($data)
    $count += 1
}
Write-Progress -id 0 -Completed -Activity $progress_activity

# Save the file
$target_file_path = Get-FileName -filter "CSV Files (*.csv)|*.csv" -dialog_type save
$datastore | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $target_file_path

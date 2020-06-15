# The prefix for the domain controllers to check (e.g., "NYC" for NYC001, NYC002, NYC003)
$target_dc_prefix = "NYC"
# The AD SearchBase (i.e., OU) to constrain getting users from (e.g., OU=Users,DC=contoso,DC=com)
$target_ad_searchbase = "OU=Main,DC=contoso,DC=com"
# Only return users older than the specified days (via Get-ADUser filter)
$days_for_filtering = 30

# Such as if you want to exclude an OU from processing (e.g., service accounts)
$distinguishedNamesToExclude = [scriptblock]{
    ($_.DistinguishedName -notlike "*,OU=MISCELLANEOUS,*") -and
}

# Convenience functions... because AD uses filetime, I guess?
function Convert-FileTimeToDateTime() {
    param(
        [Parameter(Mandatory=$true)]
        [Int64][ValidateScript({$_ -ge 0})]$time
    )
    if ($time) {
        return [datetime]::FromFileTime($time)
    }
}


function Convert-DateTimeToFileTime() {
    param(
        [Parameter(Mandatory=$true)]
        [DateTime]$datetime
    )
    if ($datetime) {
        return $datetime.ToFileTime()
    }
}


# Module imports
Import-Module -ErrorAction Stop ActiveDirectory

# Get a listing of all domain controllers for the current domain
$epoch = Get-Date
$ad_information = Get-ADDomain
$target_domain_controllers = $ad_information.ReplicaDirectoryServers -like ($target_dc_prefix + "*")

# Get a list of candidate users older than the filtered time
$filter_datetime = Convert-DateTimeToFileTime -datetime (Get-Date).AddDays(-1 * $days_for_filtering)
$users = Get-ADComputer -SearchBase $target_ad_searchbase -SearchScope Subtree -Filter "lastLogon -lt $filter_datetime"
$users = $users | Where-Object -FilterScript $distinguishedNamesToExclude


# Iterate over each user to determine--by DC--what the true last logon date was
$storage = @(); $count = 0; $progress_activity = "Getting last logon dates"
foreach($user in $users) {
    $count++
    Write-Progress -id 0 -Activity $progress_activity -CurrentOperation $user.Name -PercentComplete (100 * ($count / $users.Count))

    # Query each DC for the lastLogon of the user
    $ad_user_info_results = @() 
    foreach($dc in $target_domain_controllers) {
        Write-Progress -id 1 -Activity $progress_activity -CurrentOperation "Querying domain controller: $dc"
        $ad_user_info_results += Get-ADComputer -Identity $user -Properties lastLogon,lastLogonTimestamp,displayName -Server $dc
    }
    Write-Progress -Id 1 -Completed -Activity $progress_activity

    $lastlogon_datetimes = $ad_user_info_results | ForEach-Object {Convert-FileTimeToDateTime($_.lastLogon)}
    if ($lastlogon_datetimes) {
        $latest_logon_date = ($lastlogon_datetimes | Sort-Object -Descending)[0]
    }
    $lastlogontimestamp_datetimes = $ad_user_info_results | ForEach-Object {Convert-FileTimeToDateTime($_.lastLogonTimestamp)}
    if ($lastlogontimestamp_datetimes) {
        $latest_lastlogontimestamp_date = ($lastlogontimestamp_datetimes | Sort-Object -Descending)[0]
    }
    
    $storage += [PSCustomObject]@{
        "SamAccountName" = $ad_user_info_results[0].SamAccountName;
        "Display Name" = $ad_user_info_results[0].displayName;
        "Enabled" = $user.Enabled;
        "Last Login" = $latest_logon_date;
        "Days Since Last Login" = (New-TimeSpan -Start $latest_logon_date -End $epoch).Days;
        "Latest Last Logon Timestamp (Replicates)" = $latest_lastlogontimestamp_date;
        "Days Since Latest Last Logon Timestamp" = (New-TimeSpan -Start $latest_lastlogontimestamp_date -End $epoch).Days;
        "All Available LastLogon Dates" = $lastlogon_datetimes -join " | ";
        "All Available LastLogonTimestamp Dates" = $lastlogontimestamp_datetimes -join " | ";
        "distinguishedName" = $user.DistinguishedName;
    }
    
    # Mostly for debugging output...
    $timespan = New-TimeSpan -Start $latest_logon_date -End $epoch
    Write-Host($ad_user_info_results[0].SamAccountName + " | " + $latest_logon_date + " | " + $timespan.Days)
}
Write-Progress -id 0 -Completed -Activity $progress_activity

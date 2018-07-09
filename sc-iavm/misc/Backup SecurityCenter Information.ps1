"""
A script to export information from the user-side environment of a SecurityCenter for backup purposes.

It doesn't fully replace the need for the administrators of the server to perform backups, but it can
be useful in some instances.
"""

try {  ### Begin module import block ###
    $location_of_modules = ";$env:USERPROFILE\Documents\AuthScripts\modules"
    if ($env:PSModulePath -notlike ('*' + $location_of_modules + '*')) {
        $env:PSModulePath += $location_of_modules
    }
    Import-Module KFK-CommonFunctions -Function ("Invoke-CertificateChooser") -ErrorAction Stop
    Import-Module sc.api.core -ErrorAction Stop -DisableNameChecking
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###

$uri = ""
if ($paramSecurityCenterURI) { [string]$uri = $paramSecurityCenterURI }
$chosenCertThumb = "";
if ($paramPKIThumbprint) { [string]$chosenCertThumb = $paramPKIThumbprint }
$scToken = "";
$scriptDebug = $false
$request_throttle_msec = 350;  # Time between successive calls to the SecurityCenter, when in a loop.


function Read-ConfigFile {
    if (Test-Path .\sc.conf) {
        $conf = Get-Content .\sc.conf
        $script:uri = ($conf | ConvertFrom-Json).uri
    }
    else {
        while ($script:uri -eq "") {
            $input = Read-Host -Prompt "Provide the SecurityCenter URI, no trailing slash"
            if (($input -like "https://*") -and ($input -notlike "https://*/")) {
                $script:uri = $input
                @{ "uri" = $script:uri } | ConvertTo-Json | Out-File -FilePath .\sc.conf
            }
        }
    }
}


function Output-Debug { # Simple output if we are debugging.
    param($req)
    if ($scriptDebug) {
        $Global:DebugPreference = "Continue"
        Write-Debug $req
        $Global:DebugPreference = "SilentlyContinue"
    }
}


Read-ConfigFile

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = Invoke-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

SC-Authenticate -pkiThumbprint $chosenCertThumb -uri $uri | Out-Null

# Create the directory (at the current location) to hold the exported information
$directoryName = (Get-Date -Format yyyyMMdd) + "_SCBackup"
New-Item -ItemType Directory -Name $directoryName | Out-Null
Push-Location $directoryName

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract group information #####
$resp_groups = SC-Get-GroupInformation -name -repositories -description -definingAssets -users

$group_storage = @()
foreach($group in $resp_groups.response) {
    # Form the strings for the fields that are arrays.
    if ($group.repositories -ne $null) {
        $repos = [String]::Join("; ", $group.repositories.name)
    } else { $repos = "--NO REPOSITORIES ASSIGNED--" }
    if ($group.definingAssets -ne $null) {
        $assets = [String]::Join("; ", $group.definingAssets.name)
    } else { $assets = "--NO DEFINING ASSETS ASSIGNED--"  }
    if ($group.users -ne $null) {
        $users = [String]::Join("; ", $group.users.username)
    } else { $users = "--NO USERS ASSIGNED--" }

    $group_storage += [pscustomobject]@{
        "id" = $group.id;
        "name" = $group.name;
        "description" = $group.description -replace '[\n\r]', ' // ';
        "assignedRepositories" = $repos;
        "definingAssets" = $assets;
        "assignedUsers" = $users;
    }
}
# Write out the group information
$group_storage | ConvertTo-Csv -NoTypeInformation | Out-File group_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter group information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract user information #####
$resp_users = SC-Get-User -firstname -lastname -address -authType -city -country -email -failedLogins -fingerprint -group -lastLogin -locked -managedObjectsGroups -managedUsersGroups -createdTime -modifiedTime -mustChangePassword -phone -responsibleAsset -role -state -status -title -username -canManage -canUse

$user_storage = @()
foreach($user in $resp_users.response) {
    # Get the user's group
    foreach ($group in $resp_groups.response) {
        if ($user.id -in $group.users.id) {
            $group_name = $group.name
            break
        }
    }
    $user_storage += [pscustomobject]@{
        "id" = $user.id;
        "username" = $user.username;
        "first_name" = $user.firstname;
        "last_name"= $user.lastname;
        "title" = $user.title;
        "group_name" = $group_name;
        "address" = $user.address;
        "city" = $user.city;
        "state" = $user.state;
        "country" = $user.country;
        "email" = $user.email;
        "phone" = $user.phone;
        "authType" = $user.authType;
        "role" = $user.role.name;
        "locked" = $user.locked;
        "lastLoginUnixEpochUTC" = $user.lastLogin;
        "lastLoginDateTimeUTC" = Get-DateTimeFromUnixEpoch($user.lastLogin);
    }
}
# Write out the user information
$user_storage | ConvertTo-Csv -NoTypeInformation | Out-File user_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter user information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract scan information #####
# SC API BUG: Using ipList against the /scan endpoint does not return a CSV-list of IPs. Use ``SC-Get-ScanInfo -id $ID`` instead
#   > ipList from /scan itself: 10.10.0.010.10.0.110.10.0.2
#   > ipList from /scan/<id>: 10.10.0.0,10.10.0.1,10.10.0.2
$resp_scans = SC-Get-ScanInfo -filter manageable -name -description -type -policy -repository -zone -owner -schedule -assets -credentials -ownerGroup

$scan_storage = @()
$currProgress = 0
foreach ($scan in $resp_scans.response.manageable) {
    Write-Progress -Activity "Downloading scan information..." -CurrentOperation ("Getting info for Scan ID#" + $scan.id) -PercentComplete (($currProgress++ / $resp_scans.response.manageable.Count) * 100)
    
    # Get the ipList for the current scan (bug avoidance in the base /scan endpoint)
    $scan_resp = SC-Get-ScanInfo -id $scan.id -ipList
    
    if ($scan.assets -ne $null) {
        $assets = [String]::Join("; ", $scan.assets.name)
    } else { $assets = "--NO ASSETS ASSIGNED--" }
    if ($scan.credentials -ne $null) {
        $credentials = [String]::Join("; ", $scan.credentials.name)
    } else { $credentials = "--NO CREDENTIALS ASSIGNED--" }

    $scan_storage += [pscustomobject]@{
        "id" = $scan.id;
        "name" = $scan.name;
        "description" = $scan.description -replace '[\n\r]', ' // ';
        "ipList" = $scan_resp.response.ipList;
        "assets" = $assets
        "policy" = $scan.policy.name
        "repository" = $scan.repository.name;
        "zone" = $scan.zone.name;
        "schedule" = ($scan.schedule | ConvertTo-Json -Depth 20 -Compress).Replace('"',"'");
        "owner" = $scan.owner.username;
        "owner_group" = $scan.ownerGroup.name;
        "credentials" = $credentials;
    }

    Start-Sleep -Milliseconds $request_throttle_msec  # Throttle the requests, somewhat
}
# Export the scan information
$scan_storage | ConvertTo-Csv -NoTypeInformation | Out-File scan_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter scan information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract scan policies / download #####
$resp_scan_policies = SC-Get-ScanPolicy -filter manageable -name -description -auditFiles -owner -groups -ownerGroup

# Since we're dumping a bunch of XML files, make a separate folder
New-Item -ItemType Directory -Name "scanPolicies" | Out-Null
Push-Location "scanPolicies"
# The base path to save the downloaded files (since XML objects require the complete path)
$basePath = (Get-Location).Path + '\'

$scan_policy_storage = @()
$currProgress = 0
foreach ($policy in $resp_scan_policies.response.manageable) {
    Write-Progress -Activity "Downloading scan policy information..." -CurrentOperation ("Getting info for Scan Policy ID#" + $policy.id) -PercentComplete (($currProgress++ / $resp_scan_policies.response.manageable.Count) * 100)

    if ($policy.groups -ne $null) {
        $groups = [String]::Join("; ", $policy.groups.name)
    } else { $groups = "--NO GROUPS ASSIGNED--" }
    if ($policy.auditFiles -ne $null) {
        $auditFiles = [String]::Join("; ", $policy.auditFiles.name)
    } else { $auditFiles = "--NO AUDIT FILES ASSOCIATED--" }

    $scan_policy_storage += [pscustomobject]@{
        "id" = $policy.id;
        "name" = $policy.name;
        "description" = $policy.description -replace '[\n\r]', ' // ';
        "owner" = $policy.owner.username;
        "owner_group" = $policy.ownerGroup.name;
        "assigned_groups" = $groups;
        "audit_files" = $auditFiles;
    }

    # Get and save out the XML file
    [xml]$resp = SC-Export-ScanPolicy -scanPolicyID $policy.id
    $output_filename = Remove-InvalidFilenameCharacters -name ("scanPolicy_" + $policy.id + " - " + $policy.name + ".xml")
    # Create a directory per group, and then save the file according to the group
    $zGrpName = Remove-InvalidFilenameCharacters -name $policy.ownerGroup.name
    if (!(Test-Path -LiteralPath ($basePath + $zGrpName + "\"))) {
        New-Item -ItemType Directory -Path ($basePath + $zGrpName) | Out-Null
    }
    $resp.Save($basePath + $zGrpName + "\" + $output_filename)

    Start-Sleep -Milliseconds $request_throttle_msec  # Throttle the requests, somewhat
}
# Pop back to the main backup directory
Pop-Location
# Write out the scan policy information
$scan_policy_storage | ConvertTo-Csv -NoTypeInformation | Out-File scanPolicy_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter scan policy information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract report information / Download report templates #####
$resp_reports = SC-Get-Reports -filter 'usable,manageable' -name -description -owner -schedule -type -emailTargets -emailUsers -ownerGroup

# Since we're dumping a bunch of XML files, make a separate folder
New-Item -ItemType Directory -Name "reportTemplates" | Out-Null
Push-Location "reportTemplates"
# The base path to save the downloaded files (since XML objects require the complete path)
$basePath = (Get-Location).Path + '\'

$report_storage = @()
foreach ($report in $resp_reports.response.manageable) {
    # Save all report information for all reports (Managable and Usable)
    if ($report.groups -ne $null) {
        $emailUsers = [String]::Join("; ", $report.emailUsers.username)
    } else { $emailUsers = "--NO USER EMAIL SELECTED--" }

    $report_storage += [pscustomobject]@{
        "id" = $report.id;
        "owner" = $report.owner.username;
        "owner_group" = $report.ownerGroup.name;
        "name" = $report.name;
        # Carriage returns break Excel cells (because of course they do); replace newline and carriage returns
        "description" = $report.description -replace '[\n\r]', ' // ';
        "type" = $report.type;
        "schedule" = ($report.schedule | ConvertTo-Json -Depth 20 -Compress).Replace('"',"'");
        "emailUsers" = $emailUsers;
        "emailTargets" = $report.emailTargets;
    }
}

$currProgress = 0
foreach ($report in $resp_reports.response.usable) {
    # In their infinite wisdom, Tenable blocks exporting templates, UNLESS you:
    # a) Own the report; or
    # b) Are in the same group as the report owner.
    # So just export our reports, then.

    # Download the report teplates as a full export with references
    Write-Progress -Activity "Downloading report information..." -CurrentOperation ("Getting info for Report ID#" + $report.id) -PercentComplete (($currProgress++ / $resp_reports.response.usable.Count) * 100)

    [xml]$resp = SC-Export-ReportDefinition -reportID $report.id -type full
    $output_filename = Remove-InvalidFilenameCharacters -name ("reportTemplateWithRefs_" + $report.id + " - " + $report.name + ".xml")
    # Create a directory per group, and then save the file according to the group
    $zGrpName = Remove-InvalidFilenameCharacters -name $report.ownerGroup.name
    if (!(Test-Path -LiteralPath ($basePath + $zGrpName + "\"))) {
        New-Item -ItemType Directory -Path ($basePath + $zGrpName) | Out-Null
    }
    $resp.Save($basePath + $zGrpName + "\" + $output_filename)

    Start-Sleep -Milliseconds $request_throttle_msec  # Throttle the requests, somewhat
}
# Pop back to the main backup directory
Pop-Location
# Write out the report information
$report_storage | ConvertTo-Csv -NoTypeInformation | Out-File report_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter report information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract asset lists information / Download asset list XML files #####
$resp_assets = SC-Get-AssetList -name -description -owner -groups -ownerGroup

# Since we're dumping a bunch of XML files, make a separate folder
New-Item -ItemType Directory -Name "assetLists" | Out-Null
Push-Location "assetLists"
# The base path to save the downloaded files (since XML objects require the complete path)
$basePath = (Get-Location).Path + '\'

$asset_storage = @()
$currProgress = 0
foreach ($asset in $resp_assets.response.manageable) {
    # ID zero (0) is /technically/ an asset; but it is 'All Defined Ranges'; skip it.
    if ($asset.id -eq 0) { continue; }

    Write-Progress -Activity "Downloading asset list information..." -CurrentOperation ("Getting info for Asset ID#" + $asset.id) -PercentComplete (($currProgress++ / $resp_assets.response.manageable.Count) * 100)

    if ($asset.groups -ne $null) {
        $groups = [String]::Join("; ", $asset.groups.name)
    } else { $groups = "--NOT SHARED WITH ANY GROUPS--" }

    $asset_storage += [pscustomobject]@{
        "id" = $asset.id;
        "name" = $asset.name;
        "owner" = $asset.owner.name;
        "owner_group" = $asset.ownerGroup.name;
        "groups" = $groups;
        "description" = $asset.description -replace '[\n\r]', ' // ';
    }

    # Download the asset list template
    [xml]$resp = SC-Export-AssetList -assetListID $asset.id
    $output_filename = Remove-InvalidFilenameCharacters -name ("assetList_" + $asset.id + " - " + $asset.name + ".xml")
    # Create a directory per group, and then save the file according to the group
    $zGrpName = Remove-InvalidFilenameCharacters -name $asset.ownerGroup.name
    if (!(Test-Path -LiteralPath ($basePath + $zGrpName + "\"))) {
        New-Item -ItemType Directory -Path ($basePath + $zGrpName) | Out-Null
    }
    $resp.Save($basePath + $zGrpName + "\" + $output_filename)

    Start-Sleep -Milliseconds $request_throttle_msec  # Throttle the requests, somewhat
}
# Pop back to the main backup directory
Pop-Location
# Write out the asset information
$asset_storage | ConvertTo-Csv -NoTypeInformation | Out-File assetList_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter asset list information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract scan zone information #####
$resp_scanZones = SC-Get-ScanZone -name -description -ipList

$scanZone_storage = @()
foreach ($zone in $resp_scanZones.response) {
    $scanZone_storage += [pscustomobject]@{
        "id" = $zone.id;
        "name" = $zone.name;
        "description" = $zone.description -replace '[\n\r]';
        "ipList" = $zone.ipList;
    }
}
# Write out the scan zone information
$scanZone_storage | ConvertTo-Csv -NoTypeInformation | Out-File scanZone_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter scan zone information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract repository information #####
$resp_repositories = SC-Get-Repositories -type All -name -description -dataFormat -typeFields

$repositories_storage = @()
foreach ($repo in $resp_repositories.response) {
    $repositories_storage += [pscustomobject]@{
        "id" = $repo.id;
        "name" = $repo.name;
        "description" = $repo.description -replace '[\n\r]', ' // ';
        "dataFormat" = $repo.dataFormat;
        "ipCount" = $repo.typeFields.ipCount;
        "ipRange" = $repo.typeFields.ipRange;
    }
}
# Write out the repository information
$repositories_storage | ConvertTo-Csv -NoTypeInformation | Out-File repository_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter repository information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# ##### Extract credential metadata #####
# We can't get the actual passwords (thank Tux), but we can extract the information that the SC UI exposes.

$resp_credentials = SC-Get-CredentialInformation -name -description -type -creator -target -groups -typeFields -tags -createdTime -modifiedTime -owner -ownerGroup

$credentials_storage = @()
foreach ($cred in $resp_credentials.response.manageable) {
    if ($asset.groups -ne $null) {
        $groups = [String]::Join("; ", $asset.groups.name)
    } else { $groups = "--NOT SHARED WITH ANY GROUPS--" }

    $credentials_storage += [pscustomobject]@{
        "id" = $cred.id;
        "name" = $cred.name;
        "description" = $cred.description -replace '[\n\r]', ' // ';
        "type" = $cred.type;
        "createdTimeUTC" = Get-DateTimeFromUnixEpoch($cred.createdTime);
        "modifiedTimeUTC" = Get-DateTimeFromUnixEpoch($cred.modifiedTime);
        "groups" = $groups;
        "typeFields" = ($cred.typeFields | ConvertTo-Json -Depth 20 -Compress).Replace('"',"'");
        "creator" = $cred.creator;
        "owner" = $cred.owner.username;
        "ownerGroup" = $cred.ownerGroup.name;
    }
}

$credentials_storage | ConvertTo-Csv -NoTypeInformation | Out-File credentials_information_export.csv
Write-Host -ForegroundColor Green "Exported SecurityCenter credential information."

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Pop-Location
SC-Logout | Out-Null

Write-Host -ForegroundColor Green "~~~~~ Information Export Complete ~~~~~"

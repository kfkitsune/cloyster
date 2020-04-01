<#
Retrieve a count of operating systems as determined by the OperatingSystem field of an AD Computer object.

Limitations: The AD Computer object(s)' OperatingSystem property must be set correctly to obtain a correct number.
#>
Import-Module ActiveDirectory

# Either use the OU set here, or get base OU path based on the current domain-joined system
$ou = ""
if (!$ou) {  # If `$ou` is not set
    $Local:sys_dn_split = (Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName.Split(',')
    # Output the OU segments to the user, ignoring the CN= element (we don't care for OU purposes)
    for ($i = 1; $i -lt $Local:sys_dn_split.Length; $i++) { Write-Host '['$i' ]' $Local:sys_dn_split.Get([int]$i) }
    $Local:input = [int](Read-Host -Prompt "Enter the OU level to use as the SearchBase")
    # Rejoin the OU segments into a new OU string
    Clear-Variable -Scope Local -Name source_ou -ErrorAction SilentlyContinue # Clear this beforehand to guard against multiple runs in the same session breaking things.
    foreach ($pos in $Local:input..($Local:sys_dn_split.Length - 1)) { $Local:source_ou += $Local:sys_dn_split.Get($pos) + ',' }
    $ou = $Local:source_ou.TrimEnd(',')
}

Write-Host -ForegroundColor Cyan "Getting information from AD; this may take a moment..."
$ad_results = Get-ADComputer -SearchBase $ou -SearchScope Subtree -Filter "*" -Properties OperatingSystem,OperatingSystemVersion
Write-Host -ForegroundColor Cyan "AD Pull complete; continuing...`n`r"

$operating_systems_count = @{}

# Select each OS name set in the system properties, where it is not null...
# Extract the unique OSes
$os_names = ($ad_results | Select-Object -Unique operatingSystem | Where-Object {$_.operatingSystem -ne $null})
foreach($os_name in $os_names) {
    # Extract the versions for the OS
    $os_versions = $ad_results | Where-Object {$_.operatingSystem -eq $os_name.operatingSystem} | Select -Unique operatingSystemVersion
    foreach($os_version in $os_versions) {
        $os_name_ver = $os_name.operatingSystem + " | Version: " + $os_version.operatingSystemVersion
        # Get the count of OS per OS version
        $count = (($ad_results | Where-Object {($_.operatingSystem -eq $os_name.operatingSystem) -and ($_.operatingSystemVersion -eq $os_version.operatingSystemVersion)}) | Measure-Object).Count
        $operating_systems_count += @{$os_name_ver = $count}
        Write-Host -foregroundcolor Gray "Processed $os_name_ver ..."
    }
}

Write-Host "---------- Raw Results ----------" -ForegroundColor Green
$operating_systems_count.GetEnumerator() | Sort-Object -Property Name | Format-Table -AutoSize

# Store the Server/Workstation OS'es to group together
$server_scriptblock = [System.Management.Automation.ScriptBlock]{
    $_.OperatingSystem -like "Windows Server 2008 R2 *" -or
    $_.OperatingSystem -like "Windows Server 2012 R2 *" -or
    $_.OperatingSystem -like "Windows Server 2016 *" -or
    $_.OperatingSystem -like "Windows Server 2019 *"
}
$workstation_scriptblock = [System.Management.Automation.ScriptBlock]{
    $_.OperatingSystem -eq "Windows 7 Enterprise" -or
    $_.OperatingSystem -eq "Windows 8.1 Enterprise" -or
    $_.OperatingSystem -eq "Windows 10 Enterprise"
}

Write-Host "---------- Server Results ----------" -ForegroundColor Green
Write-Host "Count of Servers:" ($ad_results | Where-Object $server_scriptblock | Measure-Object).Count
Write-Host "---------- Workstation Results ----------" -ForegroundColor Green
Write-Host "Count of All Workstations:" ($ad_results | Where-Object $workstation_scriptblock | Measure-Object).Count

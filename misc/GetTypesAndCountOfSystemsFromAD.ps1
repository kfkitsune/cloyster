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

# Group and display results
# $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$results = $ad_results | Group-Object -Property OperatingSystem,OperatingSystemVersion | Sort-Object -Property Name | Select Name,Count
# Write-Host $stopwatch.Elapsed

Write-Host "---------- Raw Results ----------" -ForegroundColor Green
$results.GetEnumerator() | Format-Table -AutoSize

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

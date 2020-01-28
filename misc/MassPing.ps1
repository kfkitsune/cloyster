<#
A mass-ping script.

Using a source hostname/IP file, use Test-Connection to check if the targeted systems are online or not.

If hostname file is used, it should be made with one IP/hostname/DNS name per line.
#>

$job_running = $true
$subset_increment = 250
$index_lower = 0
$index_upper = $subset_increment

function Verify-ADOUExists {
    param([string]$ou)
    try {
        [adsi]::Exists("LDAP://$ou")
    }
    catch [System.Management.Automation.RuntimeException] {
        return $false
    }
}

# How are we doing this ping today?
$input = Read-Host -Prompt "To determine which systems are online...
    Do you want to: [1] Use .\hostnames.txt in the current directory
                    [2] Provide an AD LDAP OU string?
    Enter choice"
if ($input -eq 1){
    $hostname_list = Get-Content .\hostnames.txt
}
elseif ($input -eq 2) {
    Import-Module ActiveDirectory
    $ou = Read-Host -Prompt "Enter the AD OU LDAP string to act as the searchbase"
    # Keep trying to get a valid OU
    while (!(Verify-ADOUExists -ou $ou)) {
        Write-Host -ForegroundColor Red "The OU had an issue of some kind; check syntax, check if AD is up, etc. Try again. Ctrl+C to cancel."
        $ou = Read-Host -Prompt "Enter the AD OU LDAP string to act as the searchbase"
    }
    Write-Host -ForegroundColor Cyan "Getting AD Computer names..."
    $ad_results = Get-ADComputer -SearchBase $ou -SearchScope Subtree -Filter "*"
    # Get the information in the format we would expect as if we got the list straight from a file.
    $hostname_list = @()
    foreach ($dns in ($ad_results | Where-Object { $_.DNSHostName -ne $null } | Select-Object DNSHostName)) {
        $hostname_list += $dns.DNSHostName
    }
}
else {
    exit
}

# Thread-out all the ping chunks; WMI does not like super huge ping jobs, so break it up for the old geezer that WMI is (and PS doesn't handle it)
while ($index_lower -le $hostname_list.Length) {
    Test-Connection -ComputerName ($hostname_list | Select-Object -Index ($index_lower..$index_upper)) -AsJob -Delay 1 -Count 1 -ThrottleLimit 64 | Out-Null
    # Increment the subset
    $index_lower = $index_upper + 1
    $index_upper += $subset_increment
}

Write-Host -ForegroundColor Cyan "Initiating ping attempts; this may take a moment..."

# Wait until all ping jobs have completed...
while ($true) {
    if (!(Get-Job -State Running)) {
        break
    }
    Write-Progress -Activity "Waiting for ping jobs to complete" -Status ("Percent completed: " + (((Get-Job | Where-Object {$_.State -eq 'Completed'}).Count / (Get-Job).Count) * 100)) -PercentComplete (((Get-Job | Where-Object {$_.State -eq 'Completed'}).Count / (Get-Job).Count) * 100)
    Start-Sleep -Milliseconds 500
}

# Get all jobs & store the results
$completed_jobs = Get-Job -State Completed -HasMoreData $true
Clear-Variable -Name results -ErrorAction SilentlyContinue
foreach ($job in $completed_jobs) {
    $results += $job | Receive-Job | Where-Object { $_.StatusCode -eq 0 } | Select-Object Address, IPv4Address
}

# Get octets (($storage | Sort-Object -Property Octet1,Octet2,Octet3,Octet4 | ft -AutoSize))
[regex]$regex_ip_pattern = [regex]"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})"
$storage = @()
foreach ($result in $results) {
    $octets = $regex_ip_pattern.Match($result.IPV4Address)
    $storage += [pscustomobject]@{
        "Address or DNS" = $result.Address;
        "IP Address" = $result.IPv4Address;
        "Octet1" = [int]$octets.Groups[1].Value;
        "Octet2" = [int]$octets.Groups[2].Value;
        "Octet3" = [int]$octets.Groups[3].Value;
        "Octet4" = [int]$octets.Groups[4].Value;
    }
}

# Sort and output to file once complete.
$storage | Sort-Object -Property Octet1, Octet2, Octet3, Octet4 | ConvertTo-Csv -NoTypeInformation | Out-File HostsThatAreAlive.csv

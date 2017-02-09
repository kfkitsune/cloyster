<#
A mass-ping script.

Using a source hostname/IP file, use Test-Connection to check if the targeted systems are online or not.
#>

$hostname_list = Get-Content .\hostnames.txt
$job_running = $true
$subset_increment = 250
$index_lower = 0
$index_upper = $subset_increment

# Thread-out all the ping chunks; WMI does not like super huge ping jobs, so break it up for the old geezer that WMI is (and PS doesn't handle it)
while ($index_lower -le $hostname_list.Length) {
    Test-Connection -ComputerName ($hostname_list | Select-Object -Index ($index_lower..$index_upper)) -AsJob -Delay 1 -Count 1 -ThrottleLimit 64
    # Increment the subset
    $index_lower += $subset_increment
    $index_upper += $subset_increment
}

# Wait until all ping jobs have completed...
while ($true) {
    if (!(Get-Job -State Running)) {
        break
        Start-Sleep -Seconds 1
    }
}

# Get all jobs & store the results
$completed_jobs = Get-Job -State Completed -HasMoreData $true
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

<#
    Contains utility functions not directly connected to the SC API.
#>


function Get-DateTimeFromUnixEpoch() {
    <# Make a Unix epoch'd timestamp human readable. #>
    param([int64]$timestamp)
    return (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0).AddSeconds($timestamp)
}


function Get-UnixEpochFromDateTime() {
    param([DateTime]$datetime)
    return [int64]((New-TimeSpan -Start (Get-Date -Date "01/01/1970") -End $datetime).TotalSeconds)
}

# $uri = "https://the.url.would.go.here"
$uri = Read-Host -Prompt "The base URI for the SecurityCenter?"
$asset_list_quantity = 14
$asset_list_pattern = "SitePrefix - DNS - SCAP Targets - Windows 10 (Chunk NUM/14)"
<# Reverse-indexed level of the OU to collect system names from.
      -6        -5        -4       -3         -2        -1
  CN=system,OU=level3,OU=level2,OU=level1,DC=domain,dc=invalid
  If you want all systems under level1, then -3. Use
    $sys_dn_split = (Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName.Split(',')
  To obtain the correct level
#>
$ou_level = -6

try {  ### Begin module import block ###
    $location_of_modules = ";$env:USERPROFILE\Documents\AuthScripts\modules"
    if ($env:PSModulePath -notlike ('*' + $location_of_modules + '*')) {
        $env:PSModulePath += $location_of_modules
    }
    Import-Module KFK-CommonFunctions -Function ("Invoke-CertificateChooser") -ErrorAction Stop
    Import-Module sc.api.core -ErrorAction Stop -DisableNameChecking
    Import-Module ActiveDirectory
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###


$asset_list_names = @()
for($i = 0; $i -lt $asset_list_quantity; $i++) {
    $asset_list_names += $asset_list_pattern.Replace("NUM", ($i + 1 ))
}

function Split-Array ([object[]]$InputObject,[int]$SplitSize=100) {
    $length=$InputObject.Length
    for ($Index = 0; $Index -lt $length; $Index += $SplitSize) {
        #, encapsulates result in array
        #-1 because we index the array from 0
        ,($InputObject[$index..($index+$splitSize-1)])
    }
}

# Get the list of systems
Write-Host -ForegroundColor Yellow "Getting AD objects..."
$target_ou = (Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName.Split(',')[$ou_level..-1] -join ','
$ad_results = Get-ADComputer -SearchBase $target_ou -SearchScope Subtree -Filter '*' -Properties OperatingSystem

# Only select Win10, active systems, and systems we otherwise want
Write-Host -ForegroundColor Yellow "Finding valid targets..."
$targets = $ad_results | Where-Object {
    ($_.Enabled -eq $true) -and
    ($_.OperatingSystem -like "*Windows 10*") -and
    ($_.DistinguishedName -notlike "*OU=MISCELLANEOUS,*") -and
    ($_.DistinguishedName -notlike "*OU=841TB,*") -and
    ($_.DistinguishedName -notlike "*OU=596TB,*")
}

# Split the systems into managable chunks
Write-Host -ForegroundColor Yellow "Creating chunks of systems and sorting randomly..."
$chunks = Split-Array -InputObject ($targets | Sort-Object {Get-Random}) -SplitSize ($targets.Count / $asset_list_quantity)

# Authenticate to the SecurityCenter
SC-Authenticate -pkiThumbprint (Invoke-CertificateChooser) -uri $uri | Out-Null

# Get the currently defined asset lists
$sc_asset_lists = (SC-Get-AssetList -name).response.usable

# Our target asset lists
$asset_list_ids = @()
# Ensure we have all the asset lists we need to proceed
foreach($list in $sc_asset_lists) {
    if ($list.name -in $asset_list_names) {
        $asset_list_ids += $list.id
        # Write-Host $list.id
    }
}
if ($asset_list_ids.Count -ne $asset_list_quantity) {
    throw "Unable to continue; missing target asset list(s). Found" + $asset_list_ids.Count + " but expected $asset_list_quantity."
}

$pos = 0
# Set the asset lists to the target chunks
foreach($asset_id in $asset_list_ids) {
    $dns_names = ($chunks[$pos] | Select DNSHostName).DNSHostName -join ','
    SC-Patch-Asset-DNSList -id $asset_id -definedDNSNames $dns_names | Out-Null
    Write-Host -ForegroundColor Yellow "Updated asset ID $asset_id"
    Start-Sleep -Milliseconds 500
    $pos += 1
}

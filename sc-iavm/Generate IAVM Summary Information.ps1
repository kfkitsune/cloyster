param(
    [string]$paramPKIThumbprint
)

try {  ### Begin module import block ###
    Import-Module $env:USERPROFILE\Documents\AuthScripts\Modules\Get-ExcelData.psm1 -ErrorAction Stop
    Import-Module $env:USERPROFILE\Documents\AuthScripts\Modules\KFK-CommonFunctions.psm1 -Function ("Invoke-CertificateChooser") -ErrorAction Stop
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###


$chosenCertThumb = "";
if ($paramPKIThumbprint) { $chosenCertThumb = $paramPKIThumbprint }
$webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession;
$iavmSummaryWebLocation = "/iavm/iavmnotice/batchdownload.xls?iavmState=FINAL&includeNonActive=true&includeTechAdvisory=false&includeAlert=false&includeBulletin=false"
$externalConfig = $true


function Read-ConfigFile {
    $config = ""
    if ($externalConfig -and (Test-Path -Path .\downloadIAVM-HTMLFiles.conf)) {
        $config = (Get-Content -Path .\downloadIAVM-HTMLFiles.conf) -join "`n" | ConvertFrom-Json
    }
    else {
        $Local:tmp = Read-Host -Prompt "Give me the IAVM website... No trailing slash"
        $Local:zz = @{}
        $Local:zz.Add("uri", $tmp)
        $config = $Local:zz
        $Local:zz | ConvertTo-Json | Out-File -FilePath .\downloadIAVM-HTMLFiles.conf
    }
    $Script:iavmSummaryWebLocation = $config.uri + $iavmSummaryWebLocation
}


if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = Invoke-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

# Ingest URI
Read-ConfigFile

# Generate (reasonably) random filename (Date + Random + Name)
$iavmFileName = (Get-Date -UFormat "%Y%m%d") + "_" + (Get-Random -SetSeed (Get-Random) -Maximum 9999 -Minimum 2424) + "_IAVMSummary.xls"

# So get the XLS with all the XML Documents, if the file doesn't already exist. Things are fishy if this exists.
if (!(Test-Path $iavmFileName)) {
    Write-Host "Downloading IAVM Summary information..." -ForegroundColor Gray
    Invoke-RestMethod -Method Get -CertificateThumbprint $chosenCertThumb -WebSession $webSession -Uri $iavmSummaryWebLocation -OutFile $iavmFileName;
}

Write-Host "Extracting relevant information..." -ForegroundColor Gray
# Get all the columns from the only worksheet there is. ERRYTHANG!
$rawExcelData = Get-ExcelData (Resolve-Path .\$iavmFileName).Path -WorksheetName 'IAVM Summaries'
# Slice out the columns we need...
$excelData = ($rawExcelData | Select Number,Title,'STIG Finding Severity',Supersedes,'Superseded By',Status,Released,Acknowledged)

# Magic?
for ($pos=0; $pos -lt $excelData.Length; $pos++) {
    $item = $excelData.Get($pos)  # Get the item

    <#1: Trim the 'CAT ' at the front of the 'STIG Finding Severity' column #>
    $item.'STIG Finding Severity' = $item.'STIG Finding Severity'.Trim('CAT ')  # Trim 'C,A,T, '
    
    <#2: Why is there a space in front of the 'Supersedes' column? #>
    $item.Supersedes = $item.Supersedes.TrimStart(' ')

    $excelData.Set($pos, $item)  # Replace the item in the main list
}

$excelData | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath .\iavmStatus.csv

# Cleanup
Remove-Item (Resolve-Path .\$iavmFileName).Path -Force

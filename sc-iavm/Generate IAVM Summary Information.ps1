param(
    [string]$paramPKIThumbprint
)

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


function PS-CertificateChooser {
    <# Obtain listing of (potentially) valid certificates user has for authentication purposes #>
    Push-Location
    Set-Location cert:
    Set-Location \
    Set-Location Cert:\CurrentUser\My
    $certificateListing = Get-ChildItem
    Pop-Location

    <# Prompt the user for which certificate to use #>
    Write-Host("Type the number of the certificate you wish to use for authentication.")

    <# User Input: Choose which cert to use
        CHOSEN NUMBER MUST BE DECREMENTED BY ONE (1). POWERSHELL COUNTS CORRECTLY (0, 1, 2, ...)
        Starts at '1' for human-readability...
    #>
    $i = 1;
    foreach($z in $certificateListing) {
        Write-Host("[" + $i.ToString() + "] ::: " + $z.Subject + " ::: " + $z.Thumbprint)
        $i++;
    }
    $in = (Read-Host "Enter the number of the certificate to use, as shown above in brackets; e.g., '1'").ToInt32($null) - 1;

    return $certificateListing.Get($in).Thumbprint  #<--End state for this function
}

function Pause-Script ($Message = "Press any key to continue . . . ") {
	If ($psISE) {
		# The "ReadKey" functionality is not supported in Windows PowerShell ISE.

		$Shell = New-Object -ComObject "WScript.Shell"
		$Button = $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0)

		Return
	}

	Write-Host -NoNewline $Message

	$Ignore =
		16,   # Shift (left or right)
		17,   # Ctrl (left or right)
		18,   # Alt (left or right)
		20,   # Caps lock
		91,   # Windows key (left)
		92,   # Windows key (right)
		93,   # Menu key
		144,  # Num lock
		145,  # Scroll lock
		166,  # Back
		167,  # Forward
		168,  # Refresh
		169,  # Stop
		170,  # Search
		171,  # Favorites
		172,  # Start/Home
		173,  # Mute
		174,  # Volume Down
		175,  # Volume Up
		176,  # Next Track
		177,  # Previous Track
		178,  # Stop Media
		179,  # Play
		180,  # Mail
		181,  # Select Media
		182,  # Application 1
		183   # Application 2

	While ($KeyInfo.VirtualKeyCode -Eq $Null -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) {
		$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyUp")
	}

	Write-Host
}

### Import Dependencies ###
try {
    Import-Module $env:USERPROFILE\Documents\AuthScripts\Modules\Get-ExcelData.psm1 -ErrorAction Stop
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Pause-Script -Message "Press any key to exit..."
    exit
}

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = PS-CertificateChooser
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

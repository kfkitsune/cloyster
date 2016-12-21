param(
    [string]$paramPKIThumbprint
)
$chosenCertThumb = "";
if ($paramPKIThumbprint) { $chosenCertThumb = $paramPKIThumbprint }
$webSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession;
$curDate = Get-Date -UFormat "%Y%m%d"
$XMLDownloadURI = "/iavm/iavmnotice/batchdownload.zip?includeAlert=false&includeNonActive=false&includeBulletin=false&iavmState=FINAL&includeTechAdvisory=false"
$IAVMHTMLDownloadURI = "/iavm/services/notices/FOOBARBAZ.htm"  # Replace FOOBARBAZ w/ID
$EULAWarningBanner = ""
$configFileName = '.\downloadIAVM-HTMLFiles.conf'
$iavmFilenames = @{}
$externalConfig = $true

function Read-ConfigFile {
    $config = ""
    if ($externalConfig -and (Test-Path -Path $configFileName)) {
        $config = (Get-Content -Path $configFileName) -join "`n" | ConvertFrom-Json
    }
    else {
        $Local:zz = @{}
        $Local:tmp = Read-Host -Prompt "Give me the IAVM website... No trailing slash"
        $Local:zz.Add("uri", $tmp)
        $Local:tmp = Read-Host -Prompt "Give me the path to the EULA/Warning banner"
        $Local:zz.Add("eula", $tmp)
        $config = $Local:zz
        $Local:zz | ConvertTo-Json | Out-File -FilePath $configFileName
    }
    $Script:XMLDownloadURI = $config.uri + $XMLDownloadURI
    $Script:IAVMHTMLDownloadURI = $config.uri + $IAVMHTMLDownloadURI
    $Script:EULAWarningBanner = $config.uri + $config.eula
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

	#Write-Host -NoNewline $Message

	$Ignore =
		16,  # Shift (left or right)
		17,  # Ctrl (left or right)
		18,  # Alt (left or right)
		20,  # Caps lock
		91,  # Windows key (left)
		92,  # Windows key (right)
		93,  # Menu key
		144, # Num lock
		145, # Scroll lock
		166, # Back
		167, # Forward
		168, # Refresh
		169, # Stop
		170, # Search
		171, # Favorites
		172, # Start/Home
		173, # Mute
		174, # Volume Down
		175, # Volume Up
		176, # Next Track
		177, # Previous Track
		178, # Stop Media
		179, # Play
		180, # Mail
		181, # Select Media
		182, # Application 1
		183  # Application 2

	While ($KeyInfo.VirtualKeyCode -Eq $Null -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) {
		$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyUp")
	}

	Write-Host
}

Read-ConfigFile

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = PS-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

### All vs. since a date... also an exit point.
Write-Host "This script retrieves HTML files from the IAVM portal."
Write-Host "Do you want: [1] IAVMs released in the past seven (7) days;"
Write-Host "             [2] IAVMs released since a specific date; or"
Write-Host "             [3] All IAVMs."
Write-Host "Other or invalid responses exit this script."
$selection = Read-Host -Prompt "Enter your selection"
if ($selection -eq 1) {
    $date = Get-Date (Get-Date).AddDays(-7) -UFormat "%Y-%m-%d"
    $XMLDownloadURI += "&releasedStart=" + $date
}
elseif ($selection -eq 2) {  # Since a specific date: &releasedStart=2016-05-18 YYYY-MM-DD
    Write-Host "Enter a date in the format of YYYY-MM-DD. Other/Incorrect values exit."
    $selection = Read-Host -Prompt "Enter a a date in the format of YYYY-MM-DD, e.g., 2015-12-31"
    try {  ## Non-dates result in an error; head it off at the pass.
        if ((Get-Date $selection) -le (Get-Date)) {  ## Is entered date <= current date?
            $XMLDownloadURI += "&releasedStart=" + $selection
        }
        else { ## If not, exit.
            Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Invalid date entered... exiting."
            Start-Sleep -Seconds 2
            Exit
        }
    }
    catch [System.Management.Automation.ParameterBindingException] {
        Write-Host -ForegroundColor Red -BackgroundColor DarkRed "Invalid date entered... exiting."
        Start-Sleep -Seconds 2
        Exit
    }
}
elseif ($selection -eq 3) { <# "default" case #> }
else {
    Exit
}

$iavmZipFileName = "zzz_FullIAVMXMLDump.zip"
$iavmZipFileName = $iavmZipFileName.Replace("zzz",$curDate)
$iavmDirectoryName = $iavmZipFileName.Remove(24,4)

# So get the ZIP with all the XML Documents, if the file doesn't already exist.
if (!(Test-Path $iavmZipFileName)) {
    Write-Host -ForegroundColor DarkCyan Downloading and saving IAVM information for specified period
    Invoke-RestMethod -Method Get -CertificateThumbprint $chosenCertThumb -WebSession $webSession -Uri $XMLDownloadURI -OutFile $iavmZipFileName;
}

# Unzip the ZIP
if (Test-Path -Path $iavmZipFileName) {
    Add-Type -AssemblyName System.IO.Compression.Filesystem
    [IO.Compression.Zipfile]::ExtractToDirectory($iavmZipFileName,$iavmDirectoryName)
}

Push-Location #Store where we currently are for later cleanup.

# Change into the folder with the XML files for processing; only one sub-directory
Set-Location $iavmDirectoryName
Set-Location (Get-ChildItem | % { $_.FullName })

# Get all the filenames of the XML files that were downloaded.
$dirlist = Get-ChildItem -Filter *.xml
foreach ($z in $dirlist) {
    $baseLen = $z.Name.Length
    [xml]$xml = Get-Content -Path $z.Name
    $title = $xml.iavmNotice.title
    $titleLen = $title.Length
    if (($titleLen + $baseLen + 1) -gt 125) {
        $tmpstr = $z.Name.Replace(".xml", "_" + $title + ".xml")
        $tmpstr = $tmpstr.Substring(0, 121)  # Be mindful about the max path length limit (also mind we're adding 4 more characters here)
        $resultantName = $tmpstr + ".xml"
    }
    else {
        $resultantName = $z.Name.Replace(".xml", "_" + $title + ".xml")
    }
    $invalidCharacters = '[<>:"/\|?*]'  # Windows filenames cannot have these characters in them.
    $iavmFilenames.Add($iavmFilenames.Count, ($resultantName -replace $invalidCharacters,''))
}


Pop-Location # Return to base location

### Begin Process of Getting IAVM HTML Files... ###
if (Test-Path IAVM-HTML-Output) { #If the output directory already exists...
    Push-Location
    Set-Location IAVM-HTML-Output
}
else { # Doesn't exist... make it; silence output
    New-Item IAVM-HTML-Output -ItemType directory | Out-Null
    Push-Location
    Set-Location IAVM-HTML-Output
}

# Accept the EULA/System Use Notice on behalf of the user (And silence the BS)
try { Invoke-RestMethod -Method Post -CertificateThumbprint $chosenCertThumb -WebSession $webSession -Uri $EULAWarningBanner } catch { Write-Host "" -NoNewline }
try { Invoke-RestMethod -Method Post -CertificateThumbprint $chosenCertThumb -WebSession $webSession -Uri $EULAWarningBanner -Body "I Accept" } catch { Write-Host "" -NoNewline }

# Go get the HTML files based off of the ID number in the filename
$regexIAVM = [regex]"(\d{4}-[AB]-\d{4})" #Regex for IAVM ID in the filename
$regexID = [regex]"\(ID\ (\d{6})\)"      #Regex for the ID number of the HTML page
if ((Get-Variable -Name iavmFilenames -ValueOnly).Count -ge 1) {
    $local:progress = 1
    foreach($q in (Get-Variable -Name iavmFilenames -ValueOnly).GetEnumerator()) {
        $fname = [string](Split-Path $q.Value -Leaf)  #Get the filename
        $iavmValue = ($regexIAVM.Match($fname)).Value  #Get 20XX-A/B/T/-NNNN
        $iavmHTMLID = ($regexID.Match($fname)).Groups[1].Value #Get the 6 digit HTML ID
        Write-Host '('($local:progress++)/($iavmFilenames.Count)')' Saving HTML for $iavmValue from $IAVMHTMLDownloadURI.Replace("FOOBARBAZ",$iavmHTMLID)
        Invoke-RestMethod -Method Get -CertificateThumbprint $chosenCertThumb -WebSession $webSession -Uri $IAVMHTMLDownloadURI.Replace("FOOBARBAZ",$iavmHTMLID) -OutFile $fname.Replace("xml","htm")
    }
}

Pop-Location
Write-Host -ForegroundColor Cyan "Cleaning up downloaded ZIP and working directory..."
# Cleanup after ourselves... first the directory
Remove-Item -Recurse -Path $iavmDirectoryName
Remove-Item -Recurse -Path $iavmZipFileName  #Then the zip.

Write-Host -ForegroundColor Green Done.
Start-Sleep -Milliseconds 420

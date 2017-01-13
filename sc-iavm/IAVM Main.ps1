<###
Master IA Vulnerability Management Automation Script

Serves to automate the automation as much as it can be automated.
###>
try {  ### Begin module import block ###
    Import-Module $env:USERPROFILE\Documents\AuthScripts\Modules\KFK-CommonFunctions.psm1 -Function ("Invoke-CertificateChooser") -ErrorAction Stop
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###

Write-Host "~~ Script Initialization ~~" -ForegroundColor Yellow
Write-Host "Please select your PKI certificate from the following listing to use for successive authentication actions"
Write-Host ""

$selectedCertificateThumbprint = Invoke-CertificateChooser
Write-Host "Using thumbprint:" $selectedCertificateThumbprint -ForegroundColor Gray
Write-Host ""
Write-Host "Do you want to use default settings, when possible? Currently, this means retrieving the last 7 days of IAVM HTML files."
$use_defaults = Read-Host -Prompt "Enter (Y) or (N); other values default to no"
if ($use_defaults.ToLower() -eq "y") { $use_defaults = $true }
else { $use_defaults = $false }


$i = 0  # Current script number.
$j = 3  # Total scripts to launch.
Write-Host ""
Write-Host "~~ Launching scripts... ~~" -ForegroundColor Cyan
Write-Host "("(++$i)"/"($j)") IAVM/Plugin Mapping" -ForegroundColor Cyan
& '.\Nessus Plugin and IAVM Mappings.ps1' -paramPKIThumbprint $selectedCertificateThumbprint

Write-Host ""
Write-Host "("(++$i)"/"($j)") IAVM HTML Download" -ForegroundColor Cyan
& '.\Download New IAVM HTML Files.ps1' -paramPKIThumbprint $selectedCertificateThumbprint -paramUseDefaults $use_defaults

Write-Host ""
Write-Host "("(++$i)"/"($j)") IAVM Summary Information" -ForegroundColor Cyan
& '.\Generate IAVM Summary Information.ps1' -paramPKIThumbprint $selectedCertificateThumbprint

Write-Host ""
Write-Host "~~ End of script execution ~~" -ForegroundColor Green
Start-Sleep -Seconds 3

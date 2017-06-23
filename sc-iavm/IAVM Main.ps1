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

$scripts = @{
    # Execute the following tasks, using the format of:
    # 'Name of thing we are doing' = 'Location of the script.ps1';
    "IAVM/Plugin Mapping" = ".\Nessus Plugin and IAVM Mappings.ps1";
    "Download New IAVM HTML Files" = ".\Download New IAVM HTML Files.ps1";
    "Generate IAVM Summary Information" = ".\Generate IAVM Summary Information.ps1";
    "Auto Update AD DNS Asset List" = ".\Auto Update AD DNS Asset List.ps1"
}

Write-Host ""
Write-Host "~~ Launching scripts... ~~" -ForegroundColor Cyan

$count = 0
foreach ($kv in $scripts.GetEnumerator()) {
    Write-Progress -Activity "Executing scripts..." -Status ("Executing... " + $kv.Name) -PercentComplete (($count++ / $scripts.Count) * 100)
    & $kv.Value -paramPKIThumbprint $selectedCertificateThumbprint -paramUseDefaults $use_defaults
    Write-Host($kv.Name + " script execution completed.") -ForegroundColor Cyan -BackgroundColor DarkGreen
}

Write-Host ""
Write-Host "~~ Complete! ~~" -ForegroundColor Green
Start-Sleep -Seconds 3

<###
Master IA Vulnerability Management Automation Script

Serves to automate the automation as much as it can be automated.
###>

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

    return $certificateListing.Get($in).Thumbprint #<--End state for this function
}

Write-Host "~~ Script Initialization ~~" -ForegroundColor Yellow
Write-Host "Please select your PKI certificate from the following listing to use for successive authentication actions"
Write-Host ""

$selectedCertificateThumbprint = PS-CertificateChooser
Write-Host "Using thumbprint:" $selectedCertificateThumbprint -ForegroundColor Gray

$i = 0  # Current script number.
$j = 3  # Total scripts to launch.
Write-Host ""
Write-Host "~~ Launching scripts... ~~" -ForegroundColor Cyan
Write-Host "("(++$i)"/"($j)") IAVM/Plugin Mapping" -ForegroundColor Cyan
& '.\Nessus Plugin and IAVM Mappings.ps1' -paramPKIThumbprint $selectedCertificateThumbprint

Write-Host ""
Write-Host "("(++$i)"/"($j)") IAVM HTML Download" -ForegroundColor Cyan
& '.\Download New IAVM HTML Files.ps1' -paramPKIThumbprint $selectedCertificateThumbprint

Write-Host ""
Write-Host "("(++$i)"/"($j)") IAVM Summary Information" -ForegroundColor Cyan
& '.\Generate IAVM Summary Information.ps1' -paramPKIThumbprint $selectedCertificateThumbprint

Write-Host ""
Write-Host "~~ End of script execution ~~" -ForegroundColor Green
Start-Sleep -Seconds 3

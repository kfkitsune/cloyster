param(
    [string]$paramPKIThumbprint = $null,
    [string]$paramSecurityCenterURI = $null,
    [boolean]$paramUseDefaults = $true
)

<#
    Locks accounts that have not been used in a given period of time, typically according to a set policy for account management.
#>

try {  ### Begin module import block ###
    $location_of_modules = ";$env:USERPROFILE\Documents\AuthScripts\modules"
    if ($env:PSModulePath -notlike ('*' + $location_of_modules + '*')) {
        $env:PSModulePath += $location_of_modules
    }
    Import-Module KFK-CommonFunctions -Function ("Invoke-CertificateChooser") -ErrorAction Stop
    Import-Module sc.api.core -ErrorAction Stop -DisableNameChecking
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###


$uri = ""
if ($paramSecurityCenterURI) { [string]$uri = $paramSecurityCenterURI }
$chosenCertThumb = "";
if ($paramPKIThumbprint) { [string]$chosenCertThumb = $paramPKIThumbprint }
[int]$days_before_locking_account = 30
$scriptDebug = $false


function Read-ConfigFile {
    if (Test-Path .\sc.conf) {
        $conf = Get-Content .\sc.conf
        $script:uri = ($conf | ConvertFrom-Json).uri
    }
    else {
        while ($uri -eq $null) {
            $input = Read-Host -Prompt "Provide the SecurityCenter URI, no trailing slash"
            if (($input -like "https://*") -and ($input -notlike "https://*/")) {
                $script:uri = $input
                @{ "uri" = $script:uri } | ConvertTo-Json | Out-File -FilePath .\sc.conf
            }
        }
    }
}


function Output-Debug {  # Simple output if we are debugging.
    param($req)
    if ($scriptDebug) {
        $Global:DebugPreference = "Continue"
        Write-Debug $req
        $Global:DebugPreference = "SilentlyContinue"
    }
}

if (!$paramUseDefaults) {
    Write-Host -ForegroundColor Yellow "Enter the number of days before an account should be locked due to inactivity, as numeric digits."
    Write-Host -ForegroundColor Yellow "Numeric zero (0) exits. Values less than 14 days will be set to 14 days. Invalid values exit."
    try { 
        [int]$resp = Read-Host -ErrorAction Stop -Prompt "Enter a numeric number (e.g., 30)"
    } catch [System.Management.Automation.ArgumentTransformationMetadataException] {
        Throw "Entered value was non-numeric; exiting."
        exit
    }
    if ($resp -eq 0) {
        Write-Host -ForegroundColor Yellow "Exiting at user request..."
        exit
    }
    elseif ($resp -lt 14) {
        Write-Host -ForegroundColor Yellow "Entered value was below 14 days; setting to 14 days..."
        $days_before_locking_account = 14
    }
    else {
        $days_before_locking_account = $resp
    }
    Remove-Variable -Name resp -Force
}

Read-ConfigFile;

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = Invoke-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

<# Gotta log in before anything! #>
Write-Host("You may be prompted for your PIN! If so, would you kindly provide it to the dialog to permit authentication? Thanks!") -ForegroundColor Green
Write-Host("Logging in; wait...")

SC-Authenticate -pkiThumbprint $chosenCertThumb -uri $uri | Out-Null

# Get the user account information
$resp = SC-Get-User -username -lastname -firstname -email -lastLogin -locked

# Iterate over the returned account information
foreach ($account in $resp.response) {
    # Find age of account (current date - last login), via DateTime subtraction
    $age_of_account_days = ((Get-Date) - (Get-DateTimeFromUnixEpoch -timestamp $account.lastLogin)).Days
    
    # For now, ignore accounts that are already locked
    if ($account.locked -eq "true") {
        continue
    }

    if($age_of_account_days -gt $days_before_locking_account) {
        SC-Lock-User -user_id $account.id
        Write-Host -ForegroundColor Magenta "LOCKED: The account named"$account.username"<"$account.email">, has not logged in for the past $age_of_account_days days, and over the threshold of $days_before_locking_account days. As such, it has been locked."
    }
    elseif ($age_of_account_days -ge ($days_before_locking_account - 7)) {
        # Account is at most a week out from being locked; emit a warning
        Write-Host -ForegroundColor Yellow "The account named"$account.username"<"$account.email">, has not logged in for the past $age_of_account_days days. It will be locked when it has not been logged in to for $days_before_locking_account days."
    }
    Write-Host $account.username + "," + $age_of_account_days
}


SC-Logout | Out-Null

Write-Host("Accounts have been processed. Enjoy your relativistic chocolate cake.") -ForegroundColor Green
Start-Sleep -Milliseconds 420

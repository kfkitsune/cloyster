param(
    [string]$paramPKIThumbprint = $null,
    [string]$paramSecurityCenterURI = $null
)
<#
  Automatically updates a specified SecurityCenter DNS Asset list with information
    pulled directly from Active Directory, either from a supplied AD OU LDAP string,
    or manually from user-input based on the detected location of the system at
    runtime.

  Script-level parameters:
    - paramPKIThumbprint: The PKI certificate thumbprint to use for the SecurityCenter.
        Optional, however providing the parameter will prevent the user from being
        prompted during runtime. If omitted, the user will be presented with a list of
        detected PKI certificates available for authentication.
#>


###############################################################################
#-----------------These variables are intended to be edited-------------------#
###############################################################################
$target_asset_list_id = 710
$target_asset_list_name = "* - Active Directory Export"
# Use this OU instead of asking the user which OU-level they want to use
$ou = ""
# OU patterns here will be excluded from the overall results.
$excluded_ou_patterns = { $_.DistinguishedName -notmatch ",OU=MISCELLANEOUS," }
###############################################################################


try {  ### Begin module import block ###
    Import-Module .\modules\KFK-CommonFunctions.psm1 -ErrorAction Stop -DisableNameChecking
    Import-Module .\modules\sc.api.core.psm1 -ErrorAction Stop -DisableNameChecking
    Import-Module ActiveDirectory
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
$scToken = "";
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
            }
        }
    }
}


function Output-Debug { # Simple output if we are debugging.
    param($req)
    if ($scriptDebug) {
        $Global:DebugPreference = "Continue"
        Write-Debug $req
        $Global:DebugPreference = "SilentlyContinue"
    }
}


Read-ConfigFile

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = Invoke-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

SC-Authenticate -pkiThumbprint $chosenCertThumb -uri $uri | Out-Null

$resp = SC-Get-AssetList -id $target_asset_list_id -name
# Sanity check: Is this the asset list we're going after?
if ($resp.response.name -eq $target_asset_list_name) {
    if (!$ou) {  # If `$ou` is not set
        $Local:sys_dn_split = (Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName.Split(',')
        # Output the OU segments to the user, ignoring the CN= element (we don't care for OU purposes)
        for ($i = 1; $i -lt $Local:sys_dn_split.Length; $i++) { Write-Host '['$i' ]' $Local:sys_dn_split.Get([int]$i) }
        $Local:input = [int](Read-Host -Prompt "Enter the OU level to use as the SearchBase")
        # Rejoin the OU segments into a new OU string
        Clear-Variable -ErrorAction SilentlyContinue -Scope Local -Name source_ou  # Clear this beforehand to guard against multiple runs in the same session breaking things.
        foreach ($pos in $Local:input..($Local:sys_dn_split.Length - 1)) { $Local:source_ou += $Local:sys_dn_split.Get($pos) + ',' }
        $ou = $Local:source_ou.TrimEnd(',')
    }

    # Get the DNS suffix for this system
    $dns_suffix = (Get-DnsClientGlobalSetting).SuffixSearchList[0]  # Yes, this /may/ have multiple items, but I only care about the first (zeroth) element.

    Write-Host -ForegroundColor Cyan "Getting information from AD; this may take a few moments..."
    $ad_results = Get-ADComputer -SearchBase $ou -SearchScope Subtree -Filter "*"
    Write-Host -ForegroundColor Cyan "AD Pull complete; continuing...`n`r"

    Write-Host -ForegroundColor Cyan "Generating list of systems to inject into the asset list..."
    Clear-Variable -Name ad_dns_system_list -ErrorAction SilentlyContinue -Scope Local
    foreach ($system in ($ad_results | Where-Object $excluded_ou_patterns)) {
        $ad_dns_system_list += $system.Name + "." + $dns_suffix + ","
    }
    $ad_dns_system_list = $ad_dns_system_list.TrimEnd(',')

    # Now edit the asset list to reflect the fresh AD pull...
    Write-Host -ForegroundColor Cyan "Saving the new asset list definition to the SecurityCenter..."
    $description = "Export last updated: " + (Get-Date -Format yyyyMMdd)
    SC-Patch-Asset-DNSList -id $target_asset_list_id -definedDNSNames $ad_dns_system_list -description $description | Out-Null
}
else {
    throw "Sanity check failed; asset list ID does not match expected asset list name; terminating execution"
}

SC-Logout | Out-Null

Write-Host -ForegroundColor Green "AD DNS Asset List Update Successful!"
Start-Sleep -Milliseconds 420

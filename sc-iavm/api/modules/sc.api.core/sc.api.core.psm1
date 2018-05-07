<#
    Loads all SC API modules on import.

    Tenable API References: 
    a) https://docs.tenable.com/sccv/api/index.html
#>
#$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

try {  ### Begin module import block ###
    # Test for constrained language mode
    [void][Math]::Abs(1)

    # Modules to load`
    $modules = @(
        "$PSScriptRoot\sc_api_modules\sc.asset.psm1",
        "$PSScriptRoot\sc_api_modules\sc.auditfile.psm1",
        "$PSScriptRoot\sc_api_modules\sc.communication.psm1",
        "$PSScriptRoot\sc_api_modules\sc.credential.psm1",
        "$PSScriptRoot\sc_api_modules\sc.feed.psm1",
        "$PSScriptRoot\sc_api_modules\sc.file.psm1",
        "$PSScriptRoot\sc_api_modules\sc.plugin.psm1",
        "$PSScriptRoot\sc_api_modules\sc.policy.psm1",
        "$PSScriptRoot\sc_api_modules\sc.reports.psm1",
        "$PSScriptRoot\sc_api_modules\sc.repository.psm1",
        "$PSScriptRoot\sc_api_modules\sc.rolesgroups.psm1",
        "$PSScriptRoot\sc_api_modules\sc.scan.psm1",
        "$PSScriptRoot\sc_api_modules\sc.scanResult.psm1",
        "$PSScriptRoot\sc_api_modules\sc.users.psm1",
        "$PSScriptRoot\sc_api_modules\sc.zone.psm1",
        "$PSScriptRoot\sc_api_modules\utils.psm1"
    )
    foreach ($module in $modules) {
        Import-Module $module -DisableNameChecking -ErrorAction Stop
    }
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}
catch {
    if ($_.FullyQualifiedErrorID -eq "MethodInvocationNotSupportedInConstrainedLanguage") {
        throw "The SecurityCenter API modules will not function properly in constrained language mode."
    }
}

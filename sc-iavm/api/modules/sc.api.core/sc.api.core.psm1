<#
    The core module file for the PoSH SecurityCenter API.

    Loads all subresources (i.e., functions for each endpoint) via .ps1 dot-sourcing.

    Tenable API References: 
    a) https://docs.tenable.com/sccv/api/index.html
#>

try {  ### Begin module import block ###
    # Test for constrained language mode
    [void][Math]::Abs(1)

    # Subresources to load / Components of this module
    $modules = @(
        "$PSScriptRoot\sc_api_modules\sc.asset.ps1",
        "$PSScriptRoot\sc_api_modules\sc.analysis.ps1",
        "$PSScriptRoot\sc_api_modules\sc.auditfile.ps1",
        "$PSScriptRoot\sc_api_modules\sc.communication.ps1",
        "$PSScriptRoot\sc_api_modules\sc.credential.ps1",
        "$PSScriptRoot\sc_api_modules\sc.feed.ps1",
        "$PSScriptRoot\sc_api_modules\sc.file.ps1",
        "$PSScriptRoot\sc_api_modules\sc.plugin.ps1",
        "$PSScriptRoot\sc_api_modules\sc.policy.ps1",
        "$PSScriptRoot\sc_api_modules\sc.reportDefinition.ps1",
        "$PSScriptRoot\sc_api_modules\sc.repository.ps1",
        "$PSScriptRoot\sc_api_modules\sc.rolesgroups.ps1",
        "$PSScriptRoot\sc_api_modules\sc.scan.ps1",
        "$PSScriptRoot\sc_api_modules\sc.scanner.ps1",
        "$PSScriptRoot\sc_api_modules\sc.scanResult.ps1",
        "$PSScriptRoot\sc_api_modules\sc.users.ps1",
        "$PSScriptRoot\sc_api_modules\sc.zone.ps1",
        "$PSScriptRoot\sc_api_modules\utils.ps1"
    )
    foreach ($module in $modules) {
        # Load the module via dot-sourcing
        . $module
    }
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    throw "Module import failed; cannot find $module"
}
catch {
    if ($_.FullyQualifiedErrorID -eq "MethodInvocationNotSupportedInConstrainedLanguage") {
        throw "The SecurityCenter API modules will not function properly in constrained language mode."
    }
}
try {
    Add-Type -AssemblyName System.Web
}
catch {
    throw "Cannot load required type, 'System.Web'; terminating execution"
}

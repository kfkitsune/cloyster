<#
    Loads all SC API modules on import.

    Tenable API References: 
    a) https://docs.tenable.com/sccv/api/index.html
    b) https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/index.html
#>
try {  ### Begin module import block ###
    Import-Module -Name @(
        '.\modules\sc_api_modules\sc.communication.psm1',
        '.\modules\sc_api_modules\sc.asset.psm1',
        '.\modules\sc_api_modules\sc.auditfile.psm1',
        '.\modules\sc_api_modules\sc.credential.psm1',
        '.\modules\sc_api_modules\sc.feed.psm1',
        '.\modules\sc_api_modules\sc.file.psm1',
        '.\modules\sc_api_modules\sc.plugin.psm1',
        '.\modules\sc_api_modules\sc.policy.psm1',
        '.\modules\sc_api_modules\sc.reports.psm1',
        '.\modules\sc_api_modules\sc.repository.psm1',
        '.\modules\sc_api_modules\sc.rolesgroupsusers.psm1',
        '.\modules\sc_api_modules\sc.scan.psm1',
        '.\modules\sc_api_modules\sc.scanResult.psm1',
        '.\modules\sc_api_modules\sc.zone.psm1',
        '.\modules\sc_api_modules\utils.psm1'
    ) -DisableNameChecking
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
} ### End module import block ###


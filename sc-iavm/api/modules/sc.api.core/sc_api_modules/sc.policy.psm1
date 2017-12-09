<#
    Contains functions for interacting with scan policies.

    Contains the following endpoints:
      - policy
      - policy/-ID-/export
#>


function SC-Get-ScanPolicy() {
    <#
        Get the list of defined policies on the SecurityCenter.

        API Reference: https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Scan-Policy.html

        Endpoint: /rest/policy
    #>
    param(
        [switch]$name,
        [switch]$description,
        [switch]$status,
        [switch]$policyTemplate,
        [switch]$policyProfileName,
        [switch]$creator,
        [switch]$tags,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$context,
        [switch]$generateXCCDFResults,
        [switch]$auditFiles,
        [switch]$preferences,
        [switch]$targetGroup
    )
    # Build the query dict; ID number is always returned (even if id wasn't specified)
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        # Load the switch name into the fields
        $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
    }

    # Name/Description/Status come back by default if no fields are requested
    if (!($name -or $description -or $status -or $policyTemplate -or $policyProfileName -or $creator -or
          $tags -or $createdTime -or $modifiedTime -or $context -or $generateXCCDFResults -or $auditFiles -or 
          $preferences -or $targetGroup)
          ) {
        $dict.Set_Item("fields", $dict.Get_Item("fields") + ",name,description,status")
    }

    return SC-Connect -scResource policy -scHTTPMethod GET -scQueryStringDict $dict
}


function SC-Export-ScanPolicy() {
    <#
        Exports the scan policy as identified by ``scanPolicyID` and returns the XML representation of the policy,
        which can then be imported or archived.

        Parameters: scanPolicyID: The ID of the scan policy to export.

        Returns: An XML file representing the specified scan policy.

        Note: Documented in the Cerberus variant of the API, not the SCCV
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Scan-Policy.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$scanPolicyID
    )

    return SC-Connect -scResource policy/-ID-/export -scResourceID $scanPolicyID -scHTTPMethod POST
}

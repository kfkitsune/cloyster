<#
    Functions for manipulating credential objects.

    Contains the following endpoints:
      - credential
#>


function SC-Get-CredentialInformation() {
    <#
        Gets a list of all credentials from the SecurityCenter with all specified fields. If ``credentialID`` is provided,
        only return information for the credential with the ID number ``credentialID``

        Parameters:
          - credentialID: Optional. If specified, only return information for the credential whose ID number matches
              the number provided. Integer.
          - <switches>: See param() block below for information that can be returned.
    #>
    param(
        [ValidateScript({$_ -ge 0})]
          [int]$credentialID = $null,
        [switch]$name,
        [switch]$description,
        [switch]$type,
        [switch]$creator,
        [switch]$target,
        [switch]$groups,
        [switch]$typeFields,
        [switch]$tags,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$canUse,
        [switch]$canManage,
        # Session user role not "1" (Administrator)
        [switch]$owner,
        [switch]$ownerGroup,
        [switch]$targetGroup

    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('credentialID')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    if ($credentialID -eq $null) {
        $resp = SC-Connect -scResource credential -scHTTPMethod GET -scQueryStringDict $dict
    }
    else {
        # Only a specified credential is being requested.
        $resp = SC-Connect -scResource credential -scResourceID $credentialID -scHTTPMethod GET -scQueryStringDict $dict
    }
    return $resp
}

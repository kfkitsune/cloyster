<#
    Contains functions to interact with SecurityCenter user accounts.

    API Reference: https://docs.tenable.com/sccv/api/User.html
#>

function SC-Get-User() {
    <#
        Retrieves user information from the SecurityCenter, returning the specified fields.
    #>
    param(
        [switch]$username,
        [switch]$firstname,
        [switch]$lastname,
        [switch]$status,
        [switch]$role,
        [switch]$title,
        [switch]$email,
        [switch]$address,
        [switch]$city,
        [switch]$state,
        [switch]$country,
        [switch]$phone,
        [switch]$fax,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$lastLogin,
        [switch]$lastLoginIP,
        [switch]$mustChangePassword,
        [switch]$locked,
        [switch]$failedLogins,
        [switch]$authType,
        [switch]$fingerprint,
        [switch]$password,
        [switch]$description,
        [switch]$canUse,
        [switch]$canManage,
        [switch]$managedUsersGroups,
        [switch]$managedObjectsGroups,
        [switch]$preferences,
        [switch]$ldaps,
        [switch]$ldapUsername
    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource user -scHTTPMethod GET -scQueryStringDict $dict
}


function SC-Lock-User() {
    <#
        Locks a specified user account, preventing the user from logging in.

        Parameters:
          - user_id: Int. The user ID of the user to lock.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$user_id
    )
    $dict = @{"locked" = "true"}

    return SC-Connect -scResource user -scResourceID $user_id -scHTTPMethod PATCH -scJSONInput $dict
}


function SC-Unlock-User() {
    <#
        Unlocks a specified user account, permitting the user to log in.

        Parameters:
          - user_id: Int. The user ID of the user to unlock.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$user_id
    )

    $dict = @{"locked" = "false"}

    return SC-Connect -scResource user -scResourceID $user_id -scHTTPMethod PATCH -scJSONInput $dict
}


function SC-Delete-User() {
    <#
        Deletes a user from the SecurityCenter, as identified by the user's ID number.

        Requires that the 'confirm' switch be used to confirm the invoking user's/script's intention

        Parameters:
          - user_id: Int. The userID of the user to delete.
          - orgID: Int. Optional. Only if the calling user is an Administrator, the organization to delete an
              Organization Security Manager from. No effect if the calling user is a standard User.
          - confirm: Switch. Tells the function you know WTSpoon you are doing, and do actually delete the 
              specified user account. AKA, "sudo make me a sandwich", and in response I will magically transform
              you /into/ a sandwich, because you didn't specify your intention clearly enough to the djinn.

        https://docs.tenable.com/sccv/api/User.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$user_id,
        [switch]$confirm = $false,
        [ValidateScript({$_ -ge -1})]
          [int]$orgID = -1
    )
    if (!$confirm) {
        Throw "Deletion not confirmed via -confirm switch. Script execution aborted."
    }
    # The operative code here is /intentionally/ commented out here for the moment.
    elseif ($orgID -ge 0) {
        $dict = @{"orgID" = $orgID}
        # return SC-Connect -scResource user -scResourceID $user_id -scHTTPMethod DELETE -scJSONInput $dict
    }
    else {
        # return SC-Connect -scResource user -scResourceID $user_id -scHTTPMethod DELETE
    }
}

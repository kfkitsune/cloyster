<#
    Contains functions pertaining to Users, Groups, and Roles.

    Contains the following endpoints:
     - user
     - group
     - role
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


function SC-Get-GroupInformation() {
    <#
        Get a list of all groups from SecurityCenter, with the specified information.

        Parameters: See the switches in the param() block.

        Returns: A list of all groups with the specified information.

        https://docs.tenable.com/sccv/api/Group.html
    #>
    param(
        [switch]$name,
        [switch]$description,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$lces,
        [switch]$repositories,
        [switch]$definingAssets,
        [switch]$userCount,
        [switch]$users,
        [switch]$assets,
        [switch]$policies,
        [switch]$queries,
        [switch]$credentials,
        [switch]$dashboardTabs,
        [switch]$arcs,
        [switch]$auditFiles
    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource group -scHTTPMethod GET -scQueryStringDict $dict
}


function SC-Get-RoleInformation() {
    <#
        Returns a list of role information with the specified fields being returned.

        Parameters: See the param() block for a full list of switches.

        Returns: As in the function description.

        https://docs.tenable.com/sccv/api/Role.html
        https://support.tenable.com/support-center/cerberus-support-center/includes/widgets/sc_api/Role.html
    #>
    param(
        [switch]$name,
        [switch]$description,
        [switch]$creator,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$permManageApp,
        [switch]$permManageGroups,
        [switch]$permManageRoles,
        [switch]$permManageImages,
        [switch]$permManageGroupRelationships,
        [switch]$permManageBlackoutWindows,
        [switch]$permManageAttributeSets,
        [switch]$permCreateTickets,
        [switch]$permCreateAlerts,
        [switch]$permCreateAuditFiles,
        [switch]$permCreateLDAPAssets,
        [switch]$permCreatePolicies,
        [switch]$permPurgeTickets,
        [switch]$permPurgeScanResults,
        [switch]$permPurgeReportResults,
        [switch]$permScan,
        [switch]$permAgentsScan,
        [switch]$permShareObjects,
        [switch]$permUpdateFeeds,
        [switch]$permUploadNessusResults,
        [switch]$permViewOrgLogs,
        [switch]$permManageAcceptRiskRules,
        [switch]$permManageRecastRiskRules,
        [switch]$organizationCounts
    )
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -notin @('id')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource role -scHTTPMethod GET -scQueryStringDict $dict
}

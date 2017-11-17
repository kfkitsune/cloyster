<#
    Contains functions for interacting with audit files.
#>


function SC-Get-AuditFiles() {
    <#
        Gets a list of the audit files currently loaded into the SecurityCenter.

        https://docs.tenable.com/sccv/api/AuditFile.html
    #>
    param(
        [ValidateSet("usable","managable","usable,managable")]
          [string]$filter = "usable,managable",
        [switch]$name,
        [switch]$description,
        [switch]$type,
        [switch]$status,
        [switch]$groups,
        [switch]$creator,
        [switch]$version,
        [switch]$context,
        [switch]$filename,
        [switch]$originalFilename,
        [switch]$createdTime,
        [switch]$modifiedTime,
        [switch]$lastRefreshedTime,
        [switch]$canUse,
        [switch]$canManage,
        [switch]$auditFileTemplate,
        [switch]$typeFields,
        # Session User role not "1" (Administrator)
        [switch]$ownerGroup,
        [switch]$targetGroup,
        [switch]$owner
    )
    # Build the query dict
    $dict = @{
        "fields" = "id";
        "filter" = $filter
    }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        # Load the switch name into the `fields` (excluding non-switches)
        if ($key -notin @('filter')) {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }
    return SC-Connect -scResource auditFile -scHTTPMethod GET -scQueryStringDict $dict
}


function SC-Get-AuditFileTemplateCategories() {
    <#
        Gets a list of audit file categories that Tenable loads into the SecurityCenter, as seen in the
        web UI at https://acas-stew1.conus.army.mil/#audit_files/add

        Undocumented. Endpoint is at: /rest/auditFileTemplate/categories
        Request is a GET with no params.

        Example response:
            {
                "type":"regular",
                "response":[
                    {"id":"1","name":"IBM iSeries","count":"2"},
                    {"id":"10","name":"FireEye","count":"1"},
                    ...
                ],
                "error_code":0,
                "error_msg":"",
                "warnings":[],
                "timestamp":1510928689
            }

        id = ID of the category
        name = Category name
        count = How many audit files are inside the category
    #>
    return SC-Connect -scResource auditFileTemplate/categories -scHTTPMethod GET
}


function SC-Get-AuditFileTemplates() {
    <#
        Get the name of the audit file templates inside a given audit file category.

        Undocumented. Endpoint is at /rest/auditFileTemplate

        Request is a GET.

        Parameters: categoryID: Integer. The category of audit files to view.

        Example response:
        {
            "type":"regular",
            "response":[
                {"id":"152","name":"IBM System i Security Reference for V7R1 and V6R1","category":{"id":"1","name":"IBM iSeries"}},
                {"id":"151","name":"IBM iSeries Security Reference v5r4","category":{"id":"1","name":"IBM iSeries"}}
            ],
            "error_code":0,
            "error_msg":"",
            "warnings":[],
            "timestamp":1510930025
        }
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -gt 0})]
          [int]$categoryID
    )
    
    # Build the query dict
    $dict = @{
        "categoryID" = $categoryID;
        "fields" = "id,name,category"
    }

    return SC-Connect -scResource auditFileTemplate -scHTTPMethod GET -scQueryStringDict $dict
}

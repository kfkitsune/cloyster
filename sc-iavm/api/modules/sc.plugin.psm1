<#
    Functions for retrieving plugin information from the SecurityCenter.

    Contains the following endpoints:
      - plugin
#>


function SC-Get-Plugins() {
    param(
        [ValidateSet("copyright", "description", "exploitAvailable", "family", "id", "name",
                     "patchPubDate", "patchModDate", "pluginPubDate", "pluginModDate",
                     "sourceFile", "type", "version", "vulnPubDate", "xrefs")]
        [string]$filterField = "",
        [string]$xrefType = "",
        [ValidateSet("ASC", "DESC")]
          [string]$sortDirection = "DESC",
        [ValidateSet("modifiedTime", "id", "name", "family", "type")]
          [string]$sortField = "modifiedTime",
        [ValidateSet("active", "all", "compliance", "custom", "lce", "notPassive")]
          [string]$type = "all",
        [ValidatePattern("^\d+$")]
          [string]$startOffset = 0,
        [ValidatePattern("^\d+$")]
        [ValidateScript({$startOffset -le $_})]
          [string]$endOffset = 50,
        [ValidatePattern("^\d+$")]
          [int64]$secondsSinceEpoch = 0 ,
        [ValidateSet("eq", "gt", "gte", "like", "lt", "lte")]
          [string]$op = "",
        [string]$value = "",
        [string]$fields = "id,name,xrefs"
    );
    if ($xrefType -ne "") {
        $computedFilterField = $filterField + ":" + $xrefType
    }
    <# More parameter validation... #>
    if (($filterField -ne "type") -and ($filterField -ne "")) {
        if ($op -eq "") {
            Throw "The ``op`` and ``value`` parameters must be set when ``filterField`` is defined and any other value except `'type`'."
        }
    }
    elseif (($filterField -eq "type") -and ($filterField -ne "")) {
        if ($op -eq "") {
            Throw "The ``op`` and ``value`` parameters must be set when ``filterField`` is defined and of the value `'type`'."
        }
        if ($value -notin @('active', 'passive', 'lce', 'compliance', 'custom')) {
            Throw "The allowable values for the ``value`` parameter when ``filterField`` is set to `'type`' are: active, passive, lce, compliance, custom."
        }
    }

    # Build the query dict
    $dict = @{ "sortDirection" = $sortDirection;
               "sortField" = $sortField;
               "type" = $type;
               "startOffset" = $startOffset;
               "endOffset" = $endOffset;
               "since" = $secondsSinceEpoch;
               "fields" = $fields;
             }
    # If we are using any `filterField` settings, add the corresponding name/value pairs to the dict
    if ($computedFilterField -ne "") {
        $dict.Add("filterField", $computedFilterField)
        $dict.Add("op",$op)
        $dict.Add("value",$value)
    }

    $resp = SC-Connect -scResource plugin -scHTTPMethod GET -scQueryStringDict $dict
    return $resp.response
}


function SC-Get-PluginInformation() {
    <#
        Retrieves the requested information for a single plugin ID number.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({$_ -ge 0})]
          [int]$pluginID,
        [switch]$name,
        [switch]$description,
        [switch]$family,
        [switch]$type,
        [switch]$copyright,
        [switch]$version,
        [switch]$sourceFile,
        [switch]$source,
        [switch]$dependencies,
        [switch]$requiredPorts,
        [switch]$requiredUDPPorts,
        [switch]$cpe,
        [switch]$srcPort,
        [switch]$dstPort,
        [switch]$protocol,
        [switch]$riskFactor,
        [switch]$solution,
        [switch]$seeAlso,
        [switch]$synopsis,
        [switch]$checkType,
        [switch]$exploitEase,
        [switch]$exploitAvailable,
        [switch]$exploitFrameworks,
        [switch]$cvssVector,
        [switch]$cvssVectorBF,
        [switch]$baseScore,
        [switch]$temporalScore,
        [switch]$stigSeverity,
        [switch]$pluginPubDate,
        [switch]$pluginModDate,
        [switch]$patchPubDate,
        [switch]$patchModDate,
        [switch]$vulnPubDate,
        [switch]$modifiedTime,
        [switch]$md5,
        [switch]$xrefs
    )
    # Build the query dict; ID number is always returned (even if id wasn't specified)
    $dict = @{ "fields" = "id" }
    # Dynamically read the passed switches for the returned instead of a seperate line for each
    foreach ($key in $PSBoundParameters.Keys) {
        if ($key -ne 'pluginID') {
            $dict.Set_Item("fields", $dict.Get_Item("fields") + ",$key")
        }
    }

    return SC-Connect -scResource plugin -scResourceID $pluginID -scHTTPMethod GET -scQueryStringDict $dict
}
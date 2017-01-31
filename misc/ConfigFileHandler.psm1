<#
A module to uniformly handle getting/setting configuration entries within
a configuration file.

Public Function:
    a) Get-ConfigurationItem
    \-> Parameters defined in ``Get-ConfigurationItem`` docstring

Examples:
1) Set a value which requires user-input to configure.
$configUri = Get-ConfigurationItem -configFilePath $configFile -configSettingName "uri" \
    -promptIfSettingDoesntExist "Please enter the URI for the API endpoint"

2) Set a value which is set via programmatic configuration.
$secureStringKey = Get-ConfigurationItem -configFilePath $configFile -configSettingName \
    "secureStringKey" -forceValue $byteArray
#>


function Get-ConfigurationItem {
    <#
    Gets a specified configuration item from a specified configuration file. If
    the configuration item does not exist, prompt for the item, or accept input via
    parameters to set it to that value instead of prompting the user.

    Auto-creates a configuration file if necessary before proceeding.

    Parameters:
        $configFilePath: Where the configuration file for the script is supposed to live.
        $configSettingName: What setting are we looking for in the configuration file?
        $promptIfSettingDoesntExist: If the setting does not exist, the user is presented
        this string as part of the Read-Host phase to prompt them for the setting; e.g.,
        you might say, "Please provide the URI to the API endpoint for FOOBAR".
        $forceValue: Not all configuration items need a user-input value, such as the key
        for a Secure-String. This parameter force-sets the added value to this, if the
        setting does not already exist.

    Returns:
        The configuration value retrieved or set during the execution of this function.
        Handling the retrieved values is entirely up to the calling script.
    #>
    param(
        [string]$configFilePath,
        [string]$configSettingName,
        [string]$promptIfSettingDoesntExist,
        [string]$forceValue
    )
    if (!(Test-Path $configFilePath)) {  # We need to have a base XML config file to begin with.
        _Create-BaseXML -filePath $configFilePath
    }
    $xmlDocument = Get-Content -Path $configFilePath
    if (!$xmlDocument.config.$configSettingName) {  # If the setting doesn't already exist, set it.
        if ($forceValue) {  # Is this an item we don't need user-input for? E.g., Secure-String key
            $response = $forceValue
        }
        else { # We need user input for this
            $response = Read-Host -Prompt $promptIfSettingDoesntExist
        }
        _Update-Config -configFilePath $configFilePath -configSettingName $configSettingName -configSettingValue $response
        return $response
    }
    else {  # The setting exists, so get the setting.
        return $xmlDocument.config.$configSettingName
    }

}
function _Update-Config {
    param(
        [string]$configFilePath,
        [string]$configSettingName,
        [string]$configSettingValue
    )
    [xml]$config = Get-Content -Path $configFilePath
    # Get an editable XML node
    $newNode = $config.CreateElement($configSettingName)
    # Add the node (setting name only at this point) to the tree.
    $config.config.AppendChild($newNode)
    # Set the value of the new configuration item
    $config.config.$configSettingName = $configSettingValue
    # Save out the modified XML.
    $config.Save($configFilePath)
}
function _Create-BaseXML {
    <#
    Create a bare-bones XML file at the passed in file path.
    Reference: http://stackoverflow.com/questions/19245359/how-to-add-a-child-element-for-xml-in-powershell
    #>
    param(
        [string]$filePath
    )
    if (Test-Path $filePath) {
        Write-Host "Target file already exists; exiting..." -ForegroundColor Red
        Exit
    }
    '<?xml version="1.0" encoding="utf-8"?>' > $filePath
    '<config>' >> $filePath
    '  <species>kitsune</species>' >> $filePath
    '</config>' >> $filePath
}

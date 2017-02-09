<#
A module to uniformly handle getting/setting configuration entries within
a configuration file.

Public Function:
    a) Get-ConfigurationItem
    \-> Parameters defined in ``Get-ConfigurationItem`` docstring

Examples:
1) Set a value which requires user-input to configure.
$configUri = Get-ConfigurationItem -configFilePath $configFile -configSettingName "uri" \
    -configSection "example" -promptIfSettingDoesntExist "Please enter the URI for the API endpoint"

2) Set a value which is set via programmatic configuration.
$secureStringKey = Get-ConfigurationItem -configFilePath $configFile -configSettingName \
    "secureStringKey" -forceValue $byteArray -configSection "example"
#>


function Get-ConfigurationItem {
    <#
    Gets a specified configuration item from a specified configuration file. If
    the configuration item does not exist, prompt for the item, or accept input via
    parameters to set it to that value instead of prompting the user.

    Auto-creates a configuration file if necessary before proceeding.

    Parameters:
        $configFilePath: Where the configuration file for the script is supposed to live.
        $configSection: Which section of the config file are we looking in? Can be used to
        merge otherwise seperate configs for like scripts, while seperating settings visually.
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
        [Parameter(Mandatory=$true)]
        [string]$configFilePath,
        [Parameter(Mandatory=$true)]
        [string]$configSection,
        [Parameter(Mandatory=$true)]
        [string]$configSettingName,

        # One of these should ideally be set... but handle the prompt if not set.
        [string]$promptIfSettingDoesntExist,
        [string]$forceValue
    )
    if (!(Test-Path $configFilePath)) {  # We need to have a base XML config file to begin with.
        _Create-BaseXML -filePath $configFilePath
    }
    [xml]$xmlDocument = Get-Content -Path $configFilePath
    $targetSetting = $xmlDocument.SelectSingleNode('//config/script[@name="' + $configSection + '"]/' + $configSettingName)
    if (!$targetSetting) {  # If the setting doesn't already exist, set it.
        if ($forceValue) {  # Is this an item we don't need user-input for? E.g., Secure-String key
            $response = $forceValue
        }
        else { # We need user input for this
            if (!$promptIfSettingDoesntExist) {  # Be nice and set this if it is unset
                $promptIfSettingDoesntExist = "Enter a setting for '" + $configSettingName + "'."
            }
            $response = Read-Host -Prompt $promptIfSettingDoesntExist
        }
        _Update-Config -configFilePath $configFilePath -configSettingName $configSettingName -configSettingValue (_Store-Setting -setting $response) -configSection $configSection
        return $response
    }
    else {  # The setting exists, so get the setting.
        return (_Retrieve-Setting -b64Serializedinput $targetSetting.'#text')
    }

}


function _Update-Config {
    <#
    Handles writing new configuration settings to a specified configuration file, and creates
    a new section if needed.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$configFilePath,
        [Parameter(Mandatory=$true)]
        [string]$configSection,
        [Parameter(Mandatory=$true)]
        [string]$configSettingName,
        [Parameter(Mandatory=$true)]
        [string]$configSettingValue
    )
    [xml]$config = Get-Content -Path $configFilePath
    # Get an editable XML node
    $newNode = $config.CreateElement($configSettingName)
    # Does the desired section exist? If not, create it.
    $targetSection = $config.SelectSingleNode('//config/script[@name="' + $configSection + '"]')
    if (!$targetSection) {
        $sectionElem = $config.CreateElement("script")
        $sectionAtt = $config.CreateAttribute("name")
        $sectionAtt.Value = $configSection
        [void]$sectionElem.Attributes.Append($sectionAtt)
        [void]$config.config.AppendChild($sectionElem)
        $targetSection = $config.SelectSingleNode('//config/script[@name="' + $configSection + '"]')
    }
    # Add the node (setting name only at this point) to the tree.
    [void]$targetSection.AppendChild($newNode)
    # Set the value of the new configuration item
    $targetSection.$configSettingName = $configSettingValue
    # Save out the modified XML.
    $config.Save($configFilePath)
}


function _Store-Setting {
    <#
    Because some setting types (arrays) lose some data when stored, just force serialize everything,
    which saves the hassle of reconstituting most data structures, and may eliminate handling on the
    script side of the house.
    #>
    param(
        [Parameter(Mandatory=$true)]
        $setting
    )
    # First, serialize the object|input we received
    $Local:store = [System.Management.Automation.PSSerializer]::Serialize($setting)
    # Then, return a base64 string for the serialized object XML.
    return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Local:store))
}


function _Retrieve-Setting {
    <#
    The opposite of the _Store-Setting function. Un-b64 the setting string, then deserialize.
    #>
    param(
        [Parameter(Mandatory=$true)]
        $b64Serializedinput
    )
    # First, reconstitute the serialized object XML by converting back from base64.
    $Local:store = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64Serializedinput))
    # Then, return the deserialized object.
    return [System.Management.Automation.PSSerializer]::Deserialize($Local:store)
}


function _Create-BaseXML {
    <#
    Create a bare-bones XML file at the passed in file path.
    Reference: http://stackoverflow.com/questions/19245359/how-to-add-a-child-element-for-xml-in-powershell
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$filePath
    )
    if (Test-Path $filePath) {
        Write-Host "Target file already exists; exiting..." -ForegroundColor Red
        Exit
    }
    '<?xml version="1.0" encoding="utf-8"?>' > $filePath
    '<config>' >> $filePath
    '  <script name="example">' >> $filePath
    '    <species>kitsune</species>' >> $filePath
    '  </script>' >> $filePath
    '</config>' >> $filePath
}


<#
 Only export the single public function; there's no need to expose the other helpers
 and they function just fine if not exported as well.
#>
Export-ModuleMember -Function Get-ConfigurationItem

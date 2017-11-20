param(
    [string]$paramPKIThumbprint = $null,
    [string]$paramSecurityCenterURI = $null
)
<#
    Generates two files where there is a
    Plugin->IAVM mapping, and IAVM->Plugin mapping
    SecurityCenter API Level: v5.x
#>

try {  ### Begin module import block ###
    Import-Module .\modules\KFK-CommonFunctions.psm1 -ErrorAction Stop -DisableNameChecking
    Import-Module .\modules\sc.api.core.psm1 -ErrorAction Stop -DisableNameChecking
}
catch [System.IO.FileNotFoundException] {
    Write-Host -ForegroundColor Red "Unable to load required module... terminating execution..."
    Start-Sleep -Seconds 5
    exit
}      ### End module import block ###


$uri = ""
if ($paramSecurityCenterURI) { [string]$uri = $paramSecurityCenterURI }
$chosenCertThumb = "";
if ($paramPKIThumbprint) { [string]$chosenCertThumb = $paramPKIThumbprint }
$scIAVAs = @{};
$scIAVBs = @{};
$scIAVTs = @{};
$htTmpPluginToIAVM = @{};
$htTmpIAVMToPlugin = @{};
$outputFileNamePlugToIAV = "Nessus Plugin to IAVM Mapping.csv"
$outputFileNameIAVToPlug = "IAVM to Nessus Plugin Mapping.csv"
$scriptDebug = $false


function Read-ConfigFile {
    if (Test-Path .\sc.conf) {
        $conf = Get-Content .\sc.conf
        $script:uri = ($conf | ConvertFrom-Json).uri
    }
    else {
        while ($uri -eq $null) {
            $input = Read-Host -Prompt "Provide the SecurityCenter URI, no trailing slash"
            if (($input -like "https://*") -and ($input -notlike "https://*/")) {
                $script:uri = $input
                @{ "uri" = $script:uri } | ConvertTo-Json | Out-File -FilePath .\sc.conf
            }
        }
    }
}


function Output-Debug {  # Simple output if we are debugging.
    param($req)
    if ($scriptDebug) {
        $Global:DebugPreference = "Continue"
        Write-Debug $req
        $Global:DebugPreference = "SilentlyContinue"
    }
}


function Process-Xref-String {
    param(
        [ValidateSet("IAVA","IAVB","IAVT")]
          [string]$Type,
        [ValidatePattern("^\d+")]
          [string]$PluginID,
        [string]$Xrefs
    );

    $strSplit = $Xrefs.Split(", ")
    #$iavTmp = "";
    foreach($item in $strSplit.GetEnumerator()) {
        if ($item.StartsWith($type)) {  # An individual xref (e.g., "IAVA:2017-A-0040" or "OSVDB:151766")
            [void]($item -match '(?:IAV[ABT]:)(\d{4}-[ABT]-\d{4})')
            $iavm_id = $matches[1]  
            <### Plugin -> IAVM ID ###>
			try {$Script:htTmpPluginToIAVM.Add($PluginID, $iavm_id)}  <# Key doesn't exist yet, so add it in now #>
            catch [System.Management.Automation.MethodInvocationException] {  <# Key exists, so append the pluginID #>
                $mapping_value = $Script:htTmpPluginToIAVM.Get_Item($PluginID)
                # Only make the mapping if it is not already in the value
                if ($mapping_value.Split(', ') -notcontains $iavm_id) {
                    $mapping_value = $mapping_value + ", " + $iavm_id
                    $Script:htTmpPluginToIAVM.Set_Item($PluginID, $mapping_value)
                }
            }
			<### IAVM ID -> Plugin ###>
			try {$Script:htTmpIAVMToPlugin.Add($iavm_id, $PluginID)}  <# Key doesn't exist yet, so add it in now #>
            catch [System.Management.Automation.MethodInvocationException] {  <# Key exists, so append the pluginID #>
                $mapping_value = $Script:htTmpIAVMToPlugin.Get_Item($iavm_id)
                # Only make the mapping if it is not already in the value
                if ($mapping_value.Split(', ') -notcontains $PluginID) {
                    $mapping_value = $mapping_value + ", " + $PluginID
                    $Script:htTmpIAVMToPlugin.Set_Item($iavm_id, $mapping_value)
                }
            }
        }
    }
}

Read-ConfigFile;

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = Invoke-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

<# Gotta log in before anything! #>
Write-Host("You may be prompted for your PIN! If so, would you kindly provide it to the dialog to permit authentication? Thanks!") -ForegroundColor Green
Write-Host("Logging in; wait...")

SC-Authenticate -pkiThumbprint $chosenCertThumb -uri $uri | Out-Null
# Write-Host("We just got a /token/. We just got a \token\. We just got a |token|, I wonder what it is‽ ::: " + $scToken);

<# GET THOSE IAVMS! CHAAAARGE! #>
Write-Host("Acquiring IAVM IDs; wait...")
$Script:scIAVAs = SC-Get-Plugins -filterField xrefs -xrefType "IAVA" -endOffset 4000 -type active -op like -value "-A-"
Write-Host("Acquiring some additional IAVM IDs; wait some more...")
$Script:scIAVBs = SC-Get-Plugins -filterField xrefs -xrefType "IAVB" -endOffset 4000 -type active -op like -value "-B-"
Write-Host("Searching for any lost IAVM IDs; wait some more...")
$Script:scIAVTs = SC-Get-Plugins -filterField xrefs -xrefType "IAVT" -endOffset 4000 -type active -op like -value "-T-"

<# Done with SC at this point; cleanly close out the session #>
Write-Host("Logging out; wait...")
SC-Logout | Out-Null

Write-Host("Doing magic; wait...") 
<#
    We need to ferret out the unique IAVM IDs. Hashtables have to contain unique keys.
    Values can be updated via $hashtable.Set_Item(KEY,NEWVALUE)
#>
foreach($q in $scIAVAs) { <# We'll do the A's first #>
    Process-Xref-String -Type IAVA -Xrefs $q.xrefs -PluginID $q.id
}
Write-Host("Doing more magic; wait...")
foreach($q in $scIAVBs) { <# Then the B's #>
    Process-Xref-String -Type IAVB -Xrefs $q.xrefs -PluginID $q.id
}
Write-Host("Just a bit more more magic; wait...")
foreach($q in $scIAVTs) { <# Then the T's ... because completeness. #>
    Process-Xref-String -Type IAVT -Xrefs $q.xrefs -PluginID $q.id
}

<# CSV Magicks Happen Here #>
Write-Host("Exporting Plugin-to-IAVM CSV... grab a scone if you can travel at the speed of light; otherwise, wait...")
$fileWritten = 0;
while ($fileWritten -ne 1) {
    try{
        $htTmpPluginToIAVM.GetEnumerator() | Select Name, Value | Sort-Object -Property Name -Descending | 
            Export-Csv -Path $outputFileNamePlugToIAV -NoTypeInformation
        $fileWritten++
    }
    catch [System.IO.IOException] {
        Write-Host "Unable to write file... file may be open in another process..."
        Write-Host "Press any key to continue; Ctrl+C to terminate..."
        Pause-Script
    }
}
Write-Host("Exporting IAVM-to-Plugin CSV... grab a scone if you can travel at the speed of light; otherwise, wait...")
$fileWritten = 0;
while ($fileWritten -ne 1) {
    try{
        $htTmpIAVMToPlugin.GetEnumerator() | Select Name, Value | Sort-Object -Property Name -Descending | 
            Export-Csv -Path $outputFileNameIAVToPlug -NoTypeInformation
        $fileWritten++
    }
    catch [System.IO.IOException] {
        Write-Host "Unable to write file... file may be open in another process..."
        Write-Host "Press any key to continue; Ctrl+C to terminate..."
        Pause-Script
    }
}

Write-Host("Done. Enjoy your relativistic scone.") -ForegroundColor Green
Start-Sleep -Milliseconds 420

param(
    [string]$paramPKIThumbprint
)
<#
    Generates two files where there is a
    Plugin->IAVM mapping, and IAVM->Plugin mapping
#>

$scURI = ""; #Optional; Use if not using external cred/conf file.
$chosenCertThumb = "";
if ($paramPKIThumbprint) { [string]$chosenCertThumb = $paramPKIThumbprint }
$scToken = "";
$scSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession;
$scUsername = ""; #Optional; Use if not using external cred/conf file.
$scPassword = ""; #Optional; Use if not using external cred/conf file.
$scResponse = "";
$scIAVAs = @{};
$scIAVBs = @{};
$scIAVTs = @{};
$htTmpPluginToIAVM = @{};
$htTmpIAVMToPlugin = @{};
$outputFileNamePlugToIAV = "Nessus Plugin to IAVM Mapping.csv"
$outputFileNameIAVToPlug = "IAVM to Nessus Plugin Mapping.csv"
$scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList "foo", (ConvertTo-SecureString "foo" -AsPlainText -Force)
$scCredentialsFileName = ".\scCredentials.conf"
$scCredentialsKey = @(); #If changed, scCredentials.conf is invalid and must be regenerated. Can be read from conf file. 24 bytes.
$scCredentialsKeyFileName = ".\pluginIAVMMapping.conf"
$scUseExternalCredentials = $true;
$externalConfig = $true
$scriptDebug = $false

function Read-ConfigFile {
    [byte[]]$tmp = @()  # Storage for the key
    if ($externalConfig -and (Test-Path -Path $scCredentialsKeyFileName)) {
        $config = (Get-Content -Path $scCredentialsKeyFileName) -join "`n" | ConvertFrom-Json
        foreach ($i in $config.key.GetEnumerator()) {
            $tmp += [byte]$i
        }
        $script:scCredentialsKey = $tmp
    }
    else { # Generate the key, since it doesn't exist...
        #$tmp = New-Object System.Collections.ArrayList
        for ($i=0; $i -lt 24; $i++) {
            $rand = Get-Random -Minimum 0 -Maximum 255
            #$tmp.Add($rand) | Out-Null
            $tmp += [byte]$rand
        }
        $Local:zz = @{}
        $Local:zz.Add("key", $tmp)
        $Local:zz | ConvertTo-Json | Out-File -FilePath $scCredentialsKeyFileName
        if (Test-Path -Path $scCredentialsFileName) { # Remove the credentials (if they exist), since we had to generate the key (they're invalid)
            Remove-Item -Path $scCredentialsFileName
        }
        $script:scCredentialsKey = $tmp
    }
}

function Output-Debug { #Simple output if we are debugging.
    param($req)
    if ($scriptDebug) {
        Write-Host $req
    }
}
function SC-GetCredentials {
    # Do we even care about the external credentials? If not, use what's in the script.
    if ($scUseExternalCredentials -ne $true) {
        Clear-Variable -Name scCredentials -Scope Script
        $Script:scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $scUsername, (ConvertTo-SecureString $scPassword -AsPlainText -Force)
        return
    }

    <# We have stored creds... use them!
        uri = URI to /request.php
        u = Username
        p = SecureString encoded password to the username #>
    if (Test-Path -Path $scCredentialsFileName) {
        $Local:tmp = (Get-Content -Path $scCredentialsFileName) -join "`n" | ConvertFrom-Json
        Clear-Variable -Name scCredentials -Scope Script
        $Script:scCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $Local:tmp.u, (ConvertTo-SecureString $Local:tmp.p -Key $scCredentialsKey)
        $Script:scURI = $Local:tmp.uri
        
        Output-Debug $Script:scCredentials.GetNetworkCredential().UserName
        Output-Debug $Script:scCredentials.GetNetworkCredential().Password
        Output-Debug $Script:scURI
    }
    else { # Gotta make them!
        $Local:tmp = $false
        $Local:exitCount = 3
        while ($Local:tmp -ne $true) {
            try {
                Clear-Variable -Name scCredentials -Scope Script
                $Script:scCredentials = Get-Credential -Message "Enter the account to use for SecurityCenter API access."
                if ($Script:scCredentials.GetNetworkCredential().Password -ne "") {
                    $Local:tmp = $true
                }
            }
            catch [System.Management.Automation.RuntimeException] { #Highly likely the user hit cancel
                if ($Local:exitCount-- -lt 2) {
                    break
                }
                Write-Host No credentials detected... enter credentials... $Local:exitCount more to cancel...
            }
        } #End credential capture loop
        if ($Script:scURI -eq "") {
            $Script:scURI = Read-Host -Prompt "The SecurityCenter request.php URI is not defined... please enter the full URI to the request.php file."
        }
        $Local:expCreds = @{}
        <#if ($scriptDebug) {
            $Script:scCredentials.GetNetworkCredential().UserName
            $Script:scCredentials.GetNetworkCredential().Password
            Pause-Script
        }#>
        $Local:expCreds.Add("u",$scCredentials.UserName)
        $Local:expCreds.Add("p",(ConvertFrom-SecureString $scCredentials.Password -Key $scCredentialsKey))
        $Local:expCreds.Add("uri", $Script:scURI)
        $Local:expCreds | ConvertTo-Json | Out-File -FilePath $scCredentialsFileName
    }
}
function SC-BuildInputString {
    param($req);
    $requestId = Get-Random -Minimum 10000 -Maximum 19999

    # Generate the request string
    $reqStr = "request_id=" + $requestId + "&module=" + $req.module + "&action=" + $req.action + "&token=" + $Script:scToken
    
    if ($req.input -ne "") {
        $tmp = $req.input | ConvertTo-Json
        $tmp = [System.Web.HttpUtility]::UrlEncode($tmp);
        $reqStr = $reqStr + "&input=" + $tmp
    }
    return $reqStr;
}

<#
    $scJSONInput is hash table/object @{}
#>
function SC-Connect {
    param([string]$scModule, [string]$scAction, $scJSONInput);
    $request = @{"module" = $scModule;
                 "action" = $scAction;
                 "input" = $scJSONInput;}
    #echo $request;
    $requestString = SC-BuildInputString($request);
    #echo ">>SENDING<<: " $requestString

    #Send it.
    $Script:scResponse = (Invoke-RestMethod -Uri $scURI -Method POST -CertificateThumbprint $chosenCertThumb -Body $requestString -WebSession $scSession -TimeoutSec 180);
    #Write-Host("Received: " + $Script:scResponse)
    #Write-Host(">>RESPONSE CONTENTS<< ::: " + $Script:scResponse.response)
    if ($Script:scToken.Equals("")) {
        $Script:scToken = $Script:scResponse.response.token;
    }
    
}
function SC-Login {
    $json = @{}
    $json.Add("username", $scCredentials.GetNetworkCredential().UserName)
    $json.Add("password", $scCredentials.GetNetworkCredential().Password)
    SC-Connect "auth" "login" $json;
}
function SC-Logout {
    SC-Connect "auth" "logout"
}
function SC-Get-IAVA {
    $json = @{ "size" = "3000";
               "type" = "active";
               "sortField" = "id";
               "filterField" = "xrefs:IAVA";
               "filterString" = "A";};
    SC-Connect "plugin" "init" $json;
    $Script:scIAVAs = $Script:scResponse.response.plugins;
}
function SC-Get-IAVB {
    $json = @{ "size" = "3000";
               "type" = "active";
               "sortField" = "id";
               "filterField" = "xrefs:IAVB";
               "filterString" = "B";};
    SC-Connect "plugin" "init" $json;
    $Script:scIAVBs = $Script:scResponse.response.plugins;
}
function SC-Get-IAVT {
    $json = @{ "size" = "250";
               "type" = "active";
               "sortField" = "id";
               "filterField" = "xrefs:IAVT";
               "filterString" = "T";};
    SC-Connect "plugin" "init" $json;
    $Script:scIAVTs = $Script:scResponse.response.plugins;
}
function PS-CertificateChooser {
    <# Obtain listing of (potentially) valid certificates user has for authentication purposes #>
    Push-Location
    Set-Location cert:
    Set-Location \
    Set-Location Cert:\CurrentUser\My
    $certificateListing = Get-ChildItem
    Pop-Location

    <# Prompt the user for which certificate to use #>
    Write-Host("Type the number of the certificate you wish to use for authentication.")

    <# User Input: Choose which cert to use
        CHOSEN NUMBER MUST BE DECREMENTED BY ONE (1). POWERSHELL COUNTS CORRECTLY (0, 1, 2, ...)
        Starts at '1' for human-readability...
    #>
    $i = 1;
    foreach($z in $certificateListing) {
        Write-Host("[" + $i.ToString() + "] ::: " + $z.Subject + " ::: " + $z.Thumbprint)
        $i++;
    }
    $in = (Read-Host "Enter the number of the certificate to use, as shown above in brackets; e.g., '1'").ToInt32($null) - 1;

    return $certificateListing.Get($in).Thumbprint #<--End state for this function
}
function Process-Xref-String {
    param([string]$Type, 
          [string]$Xrefs,
          [string]$PluginID);

    $strSplit = $Xrefs.Split(" ")
    $iavTmp = "";
    foreach($z in $strSplit.GetEnumerator()) {
            #Write-Host($z)
        if ($z.StartsWith($type)) {
            $iavTmp = $z.Trim(",")
            $iavTmp = $iavTmp.Replace($type + ":","") <# Superfluous; Kill the IAVA: IAVB: prefix #>
            #Write-Host($iavTmp)
            <### Plugin -> IAVM ID ###>
			try {$Script:htTmpPluginToIAVM.Add($PluginID, $iavTmp)} <# Key doesn't exist yet, so add it in now #>
            catch [System.Management.Automation.MethodInvocationException] { <# Key exists, so append the pluginID #>
                #Write-Host(">>> IAVM ID <<<" + $iavTmp)
                $qq = $Script:htTmpPluginToIAVM.Get_Item($PluginID)
                $qq = $qq + ", " + $iavTmp
                $qq = $qq.TrimStart(", ") <# Because gremlins. #>
                #Write-Host($qq)
                $Script:htTmpPluginToIAVM.Set_Item($PluginID, $qq)
            }
			<### IAVM ID -> Plugin ###>
			try {$Script:htTmpIAVMToPlugin.Add($iavTmp, $PluginID)} <# Key doesn't exist yet, so add it in now #>
            catch [System.Management.Automation.MethodInvocationException] { <# Key exists, so append the pluginID #>
                #Write-Host(">>> IAVM ID <<<" + $iavTmp)
                $qq = $Script:htTmpIAVMToPlugin.Get_Item($iavTmp)
                $qq = $qq + ", " + $PluginID
                $qq = $qq.TrimStart(", ") <# Because gremlins. #>
                #Write-Host($qq)
                $Script:htTmpIAVMToPlugin.Set_Item($iavTmp, $qq)
            }
        }
    }
}
function Pause-Script ($Message = "Press any key to continue . . . ") {
	If ($psISE) {
		# The "ReadKey" functionality is not supported in Windows PowerShell ISE.

		$Shell = New-Object -ComObject "WScript.Shell"
		$Button = $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0)

		Return
	}

	#Write-Host -NoNewline $Message

	$Ignore =
		16,  # Shift (left or right)
		17,  # Ctrl (left or right)
		18,  # Alt (left or right)
		20,  # Caps lock
		91,  # Windows key (left)
		92,  # Windows key (right)
		93,  # Menu key
		144, # Num lock
		145, # Scroll lock
		166, # Back
		167, # Forward
		168, # Refresh
		169, # Stop
		170, # Search
		171, # Favorites
		172, # Start/Home
		173, # Mute
		174, # Volume Down
		175, # Volume Up
		176, # Next Track
		177, # Previous Track
		178, # Stop Media
		179, # Play
		180, # Mail
		181, # Select Media
		182, # Application 1
		183  # Application 2

	While ($KeyInfo.VirtualKeyCode -Eq $Null -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) {
		$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyUp")
	}

	Write-Host
}

Read-ConfigFile;
SC-GetCredentials;

if ($chosenCertThumb -eq "") {  # Only execute if we don't have a thumbprint from the commandline
    <# WHO AM I? //WHAT YEAR IS IT?!// #>
    $chosenCertThumb = PS-CertificateChooser
    Write-Host("Chosen certificate thumbprint ::: " + $chosenCertThumb)
}

<# Gotta log in before anything! #>
Write-Host("You may be prompted for your PIN! If so, kindly provide it to the dialog to permit authentication. Thanks!") -ForegroundColor Green
Write-Host("Logging in; wait...")
SC-Login;
#Write-Host("We just got a /token/. We just got a \token\. We just got a |token|, I wonder what it is‽ ::: " + $scToken);

<# GET THOSE IAVMS! CHAAAARGE! #>
Write-Host("Acquiring IAVM IDs; wait...")
SC-Get-IAVA;
Write-Host("Acquiring some additional IAVM IDs; wait some more...")
SC-Get-IAVB;
Write-Host("Searching for any lost IAVM IDs; wait some more...")
SC-Get-IAVT;

<# Done with SC at this point; cleanly close out the session #>
Write-Host("Logging out; wait...")
SC-Logout;

Write-Host("Doing magic; wait...") 
<#
    We need to ferret out the unique IAVM IDs. Hashtables have to contain unique keys.
    Values can be updated via $hashtable.Set_Item(KEY,NEWVALUE)
#>
foreach($q in $scIAVAs) { <# We'll do the A's first #>
    Process-Xref-String -Type "IAVA" -Xrefs $q.xrefs -PluginID $q.id
}
Write-Host("Doing more magic; wait...")
foreach($q in $scIAVBs) { <# Then the B's #>
    Process-Xref-String -Type "IAVB" -Xrefs $q.xrefs  -PluginID $q.id
}
Write-Host("Just a bit more more magic; wait...")
foreach($q in $scIAVTs) { <# Then the T's ... because completeness. #>
    Process-Xref-String -Type "IAVT" -Xrefs $q.xrefs  -PluginID $q.id
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

<#
Commonly used script functions.
#>
function Pause-Script ($Message = "Press any key to continue . . . ") {
	If ($psISE) {
		# The "ReadKey" functionality is not supported in Windows PowerShell ISE.
		$Shell = New-Object -ComObject "WScript.Shell"
		$Button = $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0)
		Return
	}
	Write-Host -NoNewline $Message
	$Ignore =
        <# Format: Keycode, \<#Explanation of what keycode is#\> #>
		 16,  <# Shift (left or right) #>  17,  <# Ctrl (left or right) #>   18,  <# Alt (left or right) #>
         20,  <# Caps lock #>              91,  <# Windows key (left) #>     92,  <# Windows key (right) #>
		 93,  <# Menu key #>              144,  <# Num lock #>              145,  <# Scroll lock #>
		166,  <# Back #>                  167,  <# Forward #>               168,  <# Refresh #>
		169,  <# Stop #>                  170,  <# Search #>                171,  <# Favorites #>
		172,  <# Start/Home #>            173,  <# Mute #>                  174,  <# Volume Down #>
		175,  <# Volume Up #>             176,  <# Next Track #>            177,  <# Previous Track #>
		178,  <# Stop Media #>            179,  <# Play #>                  180,  <# Mail #>
		181,  <# Select Media #>          182,  <# Application 1 #>         183   <# Application 2 #>

	While ($KeyInfo.VirtualKeyCode -Eq $Null -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) {
		$KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyUp")
	}
	Write-Host
}

function Invoke-CertificateChooser {
    <#
    Displays a listing of the currently logged on user's PKI certificates,
    and returns a chosen thumbprint of the certificate.

    Parameters:
        None

    Returns:
        The chosen PKI certificate thumbprint.
    #>
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

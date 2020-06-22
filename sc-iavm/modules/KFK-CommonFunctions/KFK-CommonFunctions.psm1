<#
Commonly used script functions. Because a single source of truth beats copied code in
individual scripts.
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


function Remove-InvalidFilenameCharacters() {
    <#
    Creates a sanitized Windows-acceptable filename (everything invalid is simply stripped)
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$name
    )
    $invalidCharacters = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [Regex]::Escape($invalidCharacters)
    $tmp = $name -replace $re
    # Windows has a 255 maxlength on a filename... truncate to 255.
    return (($tmp).Substring(0, [System.Math]::Min(255, $tmp.Length)))
}


function Get-FileName() {
    <#
    Retrieve a file name from a GUI-based file picker

    Parameters:
      - initialDirectory: String. The file path to set the file picker to initially.
      - filter: String. Determines the choices that appear in the "Save as file type" or "Files of type" box in the dialog box
      Ref: https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.filedialog.filter
      Defaults to all files ("All files (*.*)|*.*").
      - dialog_type: String/Switch. Whether this should be a save or open dialog. Defaults to open. Only valid for 'open' or 'save'.`
    
    Returns:
        The full path to the selected file
    #>  # Yes, it's a Pythonic comment... hiss!
    param(
        [string]$initial_directory,
        [string]$filter = "All files (*.*)|*.*",
        [ValidateSet("save","open")]
          [string]$dialog_type = "open"
    )
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    if ($dialog_type -eq "open") {
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    }
    else {
        $OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    }
    $OpenFileDialog.initialDirectory = $initial_directory
    $OpenFileDialog.filter = @($filter)
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}


function Convert-FileTimeToDateTime() {
    <#
        Converts a Windows filetime to a DateTime object.

        Ref: https://docs.microsoft.com/en-us/windows/win32/sysinfo/file-times

        Parameters:
          - time: int64. The file time to convert
          - from_utc: Switch. Converts the specified Windows file time to an equivalent UTC time.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [Int64][ValidateScript({$_ -ge 0})]$time,
        [switch]$from_utc
    )
    if ($from_utc) {
        return [DateTime]::FromFileTimeUtc($time)
    }
    else {
        return [datetime]::FromFileTime($time)
    }
}


function Convert-DateTimeToFileTime() {
    <#
        Converts a DateTime object to a Windows filetime int64.

        Ref: https://docs.microsoft.com/en-us/windows/win32/sysinfo/file-times

        Parameters:
          - datetime: DateTime object. The DateTime to convert to a filetime
          - to_utc: Switch. Converts the specified UTC DateTime to an equivalent UTC file time.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [DateTime]$datetime,
        [switch]$to_utc
    )
    if ($to_utc) {
        return $datetime.ToFileTimeUtc()
    }
    else {
        return $datetime.ToFileTime()
    }
}

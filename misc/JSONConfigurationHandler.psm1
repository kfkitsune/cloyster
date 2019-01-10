function Read-JSONConfigurationFile() {
    <#
        Reads a JSON configuration file, and returns a PoSH dictionary of the deseralized JSON content.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [String]$FileName
    )
    $file_content = Get-Content -Raw -Path $FileName

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # -AsHashtable introduced in PoSH v6.0
        $hashtable = $file_content | ConvertFrom-Json -AsHashtable
    }
    else {
        $hashtable = @{}
        (ConvertFrom-Json $file_content).PSObject.Properties | ForEach { $hashtable[$_.Name] = $_.Value }
    }
    
    return $hashtable
}

function Write-JSONConfigurationFile() {
    <#
        Write a configuration file out to disk with the incoming PoSH dictionary object,
        deserializing the dict to JSON.

        Parameters:
        - ConfObj: HashTable. The PoSH dictionary/HT to deserialize as JSON and write out.
        - FilePath: String. The path of the file to write out.
        - Clobber: Switch. If set, overwrites the targeted file at $FilePath, if it exists.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [HashTable]$ConfObj,
        [Parameter(Mandatory=$true)]
          [String]$FilePath,
        [switch]$Clobber
    )
    if (!$Clobber.IsPresent) {
        # Don't clobber the target filename (if it exists)
        ConvertTo-Json -Depth 100 $ConfObj | Out-File -FilePath $FilePath -NoClobber
    }
    else {
        ConvertTo-Json -Depth 100 $ConfObj | Out-File -FilePath $FilePath
    }
}

function Read-JSONConfigurationFile() {
    <#
        Reads a JSON configuration file, and returns a PoSH dictionary of the deseralized JSON content.

        Optionally, retrieves a single top-level key from the deserialized JSON. Useful for retrieving
        a configuration 'section'.

        Parameters:
          - FilePath: String. The full path and filename to a JSON configuration file.
          - Section: String. Retrieves a specified top-level value from the deserialized JSON.
    #>
    param(
        [Parameter(Mandatory=$true)]
          [String]$FilePath,
        [String]$Section
    )
    $file_content = Get-Content -Raw -Path $FilePath

    if ($PSVersionTable.PSVersion.Major -ge 6) {
        # -AsHashtable introduced in PoSH v6.0
        $hashtable = $file_content | ConvertFrom-Json -AsHashtable
    }
    else {
        $hashtable = @{}
        (ConvertFrom-Json $file_content).PSObject.Properties | ForEach { $hashtable[$_.Name] = $_.Value }
    }
    
    if ($Section) {
        return $hashtable.$Section
    }
    else {
        return $hashtable
    }
}

function Write-JSONConfigurationFile() {
    <#
        Write a configuration file out to disk with the incoming PoSH dictionary object,
        deserializing the dict to JSON.

        Parameters:
        - ConfObj: HashTable. The PoSH dictionary/HT to deserialize as JSON and write out.
        - FilePath: String. The path of the file to write out.
        - NoClobber: Switch. If set, does not clobber any existing file at the specified
          FilePath (as per `Out-File -NoClobber).
        - Compress: Switch. If set, compresses the serialized JSON output (as
          `ConvertTo-Json -Compress` would).
    #>
    param(
        [Parameter(Mandatory=$true)]
          [HashTable]$ConfObj,
        [Parameter(Mandatory=$true)]
          [String]$FilePath,
        [switch]$NoClobber,
        [switch]$Compress
    )
    ConvertTo-Json -Depth 100 -Compress:$Compress | Out-File -FilePath $FilePath -NoClobber:$NoClobber
}

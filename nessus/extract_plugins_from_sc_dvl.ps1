<#
    Takes a detailed vulnerability list from SecurityCenter as the input file

    Because sometimes you recognize that CSV files are absolutely garbage for processing.
    Yes, PowerShell does have Import-Csv.
    Yes, Import-Csv does work well.
    No, Import-Csv does not work well with monstrously huge CSV files.

    So we just need to pull out what we are targeting.
#>

Function Get-FileName($initialDirectory) {
    <#
    Retrieve a file name from a GUI-based file picker

    Parameters:
        $initialDirectory: The file path to set the file picker to initially
    
    Returns:
        The full path to the selected file
    #>  # Yes, it's a Pythonic comment... hiss!
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "CSV (*.csv)| *.csv"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.filename
}

# Name of the output file?
$filename = (Get-Location).Path + "\infoDump.csv"
if (Test-Path($filename)) {
    Write-Host("ERROR: " + $filename + " exists; I'm not going to clobber it. Terminating.") -ForegroundColor Red
    throw "File exists"
}

# Which plugins are we looking to export from the massive CSV?
$target_plugins = @(
    10400, # Mandrake Linux Security Advisory : slocate (MDKSA-2003:015)
    10428, # Microsoft Windows SMB Registry Not Fully Accessible Detection.
    11936, # OS Identification;
    12643, # IMP Software Detection
    19506, # Nessus Scan Information;
    21745, # Authentication Failure - Local Checks Not Run;
    23974, # Microsoft Windows SMB Share Hosting Office Files
    24786, # Nessus Windows Scan Not Performed with Admin Privileges;
    26917, # Microsoft Windows SMB Registry: Nessus Cannot Access the Windows Registry;
    92428  # Recent File History
)
[regex]$target_plugin_csv_pattern = "^`"(\d{5})`",`".*"

# Create a StreamReader object (because large files make PoSH choke)
$stream_reader = New-Object System.IO.StreamReader(Get-FileName(Get-Location))
# Create the StreamWriter (so we don't incur IO penalties)
$stream_writer = New-Object System.IO.StreamWriter($filename)

# Get the headers for the file
$headers = $stream_reader.ReadLine()

# Write the headers
$stream_writer.WriteLine($headers)

# For some measure of progress tracking
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$elapsed_seconds = 0

$stored_line = ""

# Continue to read until the end of the stream is reached...
while (!$stream_reader.EndOfStream) {
    # Do we have a plugin previously ingested, and did it match what we are looking for?
    if ($Matches -and ($Matches[1] -in $target_plugins)) {
        # The stored like begins a plugin, so we need to store it before we continue
        $plugin_storage = @($stored_line)

        # Keep reading in lines until we get to a new plugin matching our pattern.
        while (!(($line = $stream_reader.ReadLine()) -match $target_plugin_csv_pattern)) {
            $plugin_storage += $line
        }
        # Store the line for the next iteration of the loop
        $stored_line = $line

        # Write out the completed plugin
        $stream_writer.WriteLine($plugin_storage -join " ")
    }
    # If not, then get the next line, see if it matches our regex pattern, and store it if it does
    elseif ((($line = $stream_reader.ReadLine()) -match $target_plugin_csv_pattern)) {
        $stored_line = $line
    }

    # So we can have some sort of 'progress' and show that the script hasn't crashed (otherwise it's silent during execution.
    if ($sw.Elapsed.TotalMilliseconds -ge 5000) {
        $dur = [Math]::Round(($elapsed_seconds / 60), 2)
        Write-Progress -Activity "Elapsed time..." -Status "$dur minutes..."
        $sw.Reset(); $sw.Start()
        $elapsed_seconds += 5
    }
}

# Close out the file.
$stream_writer.Close()
$stream_reader.Close()

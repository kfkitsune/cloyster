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
$filename = "infoDump.csv"
# Which plugins are we looking to export from the massive CSV?
$target_plugins = @(26917, 24786, 21745, 19506, 11936, 10428)
[regex]$target_plugin_csv_pattern = "^`"(\d{5})`",`".*"

$stream_reader = New-Object IO.StreamReader(Get-FileName(Get-Location))
# Get the headers for the file
$headers = $stream_reader.ReadLine()

# Write the headers
$headers | Out-File -FilePath $filename

$stored_line = ""
while (!$stream_reader.EndOfStream) {
    # Do we have a plugin previously ingested, and did it match what we are looking for?
    if (($stored_line -match $target_plugin_csv_pattern) -and
                       ($Matches[1] -in $target_plugins)) {
        $plugin_storage = @($stored_line)
        while (!(($line = $stream_reader.ReadLine()) -match $target_plugin_csv_pattern)) {
            $plugin_storage += $line
        }
        # Store the line for the next iteration of the loop
        $stored_line = $line

        # Write out the completed plugin
        $plugin_storage -join " " | Out-File -Append -FilePath $filename
    }
    # If not, then get the next line, and store it
    elseif ((($line = $stream_reader.ReadLine()) -match $target_plugin_csv_pattern) -and
                                              ($Matches[1] -in $target_plugins)) {
        $stored_line = $line
    }
}

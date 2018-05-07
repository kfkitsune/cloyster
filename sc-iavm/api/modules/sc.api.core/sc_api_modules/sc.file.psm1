<#
    Functions for uploading a file to the SecurityCenter for various purposes

    Contains the following endpoints:
     - file/upload
#>


function SC-Upload-File() {
    <#
        A semi-loosely documented endpoint. It's documented, just not for all use-cases. Designed currently
        to import Nessus results. Unsure if it will work as-is to upload other file types.

        https://docs.tenable.com/sccv/api/File.html
    #>
    param(
        [Parameter(Mandatory=$true)]
        $filePath
    )
    # Write-Host $filePath
    # Read in the entire file
    $fileBin = [IO.File]::ReadAllBytes($filePath)
    # Safely encode the file for transfer
    $fileEnc = [System.Text.Encoding]::GetEncoding("ISO-8859-1").GetString($fileBin)
    # Make a boundary to deliniate where the file information is
    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    $fileName = (Split-Path -Leaf $filePath)
    # Manually build the request payload, doing something like ``@(foo,bar,baz) -join $LF`` adds spaces in spots and mucks it up.
    $uploadBody = "----------$boundary" + $LF
    $uploadBody += "Content-Disposition: form-data; name=`"Filedata`"; filename=`"$fileName`"$LF"
    $uploadBody += "Content-Type: application/octet-stream$LF$LF"
    $uploadBody += $fileEnc + $LF
    $uploadBody += "----------$boundary--"
    # Add in the additional headers required for this API endpoint
    $additionalHeaders = @{"Content-Type"="multipart/form-data; boundary=--------$boundary"}
    $resp = SC-Connect -scResource file/upload -scHTTPMethod POST -scAdditionalHeadersDict $additionalHeaders -scRawRequestPayload $uploadBody
    # The name of the file on the SecurityCenter server to be used for other actions (such as importing)
    return $resp.response.filename
}

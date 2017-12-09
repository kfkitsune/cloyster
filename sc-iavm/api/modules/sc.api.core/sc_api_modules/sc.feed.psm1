<#
    Contains functions for viewing feed information.

    Contains the following endpoints:
      - feed
#>

function SC-Get-FeedInformation() {
    <#
        Gets the status of feed uploads (last update time, is it stale, and is an update running).
        Displays info for all feeds (sc, active, passive, lce).

        Parameters: None

        Returns: As it says in the function description.

        https://docs.tenable.com/sccv/api/Feed.html
    #>
    return SC-Connect -scResource feed -scHTTPMethod GET
}

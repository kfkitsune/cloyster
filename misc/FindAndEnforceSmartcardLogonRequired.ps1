<#
Find accounts in Active Directory that do not have the SmartCardLogonRequired bit set.
#>

# We need admin... are we admin? If not, attempt to elevate to admin.
# http://blogs.msdn.com/b/virtual_pc_guy/archive/2010/09/23/a-self-elevating-powershell-script.aspx
Write-Host -ForegroundColor Green "Attempting to elevate to Administrator-level permissions..."
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
if ($myWindowsPrincipal.IsInRole($adminRole)) {
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
   Write-Host -ForegroundColor Yellow "Elevation complete. You are now free to move about the shell."
}
else {
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   $strArguments = '-ExecutionPolicy Unrestricted -file "' + $myInvocation.MyCommand.Definition + '"' + ' -newPath "' + (Get-Location).Path + '"'
   $newProcess.Arguments = $strArguments
   $newProcess.Verb = "runas";
   [System.Diagnostics.Process]::Start($newProcess);
   exit
}
###############################################################################

Import-Module ActiveDirectory
# Get the AD User accounts, and include Smartcard Logon Required, Description, and Group Membership
# Either use the OU set here, or get base OU path based on the current domain-joined system
$ou = ""
if (!$ou) {  # If `$ou` is not set
    $Local:sys_dn_split = (Get-ADComputer -Identity $env:COMPUTERNAME).DistinguishedName.Split(',')
    # Output the OU segments to the user, ignoring the CN= element (we don't care for OU purposes)
    for ($i = 1; $i -lt $Local:sys_dn_split.Length; $i++) { Write-Host '['$i' ]' $Local:sys_dn_split.Get([int]$i) }
    $Local:input = [int](Read-Host -Prompt "Enter the OU level to use as the SearchBase")
    # Rejoin the OU segments into a new OU string
    if ($Local:source_ou) { Clear-Variable -Scope Local -Name source_ou }  # Clear if set to prevent multiple execution runs in the same console session from breaking it.
    foreach ($pos in $Local:input..($Local:sys_dn_split.Length - 1)) { $Local:source_ou += $Local:sys_dn_split.Get($pos) + ',' }
    $ou = $Local:source_ou.TrimEnd(',')
}

# We're looking for Enabled accounts that do not have the SmartCardLogonRequired bit set
$ad_filter = {(Enabled -eq $true) -and 
              (SmartCardLogonRequired -eq $false)
             }

Write-Host -ForegroundColor Cyan "Getting information from AD; this may take a moment..."
$ad_users = Get-ADUser -SearchBase $ou -SearchScope Subtree -Filter $ad_filter -Properties SmartcardLogonRequired,Description,MemberOf

# Add and/or modify as needed to exclude OUs or Users that should not be enforced (AKA, service accounts, or otherwise)
$scl_exempt_filter = { $_.DistinguishedName -notmatch ".*(,OU=(Classroom|SVC|Service|CCL\ Exempt.*)\ Accounts,).*" }

$not_scl_enforced = $ad_users | Where-Object $scl_exempt_filter

Write-Host -ForegroundColor Red "`r`nThe following accounts are do NOT have the SmartcardLogonRequired bit set..."
$not_scl_enforced | Select-Object Name,SamAccountName,Description | Format-Table -AutoSize

$in = Read-Host "Set SmartcardLogonRequired for all accounts identified above? Y/N"
if ($in.ToLower() -eq "y") {
    foreach ($user in $not_scl_enforced) {
        Write-Host("Setting SmartcardLogonRequired flag for: " + $user.DistinguishedName)
        Set-ADUser -Identity $user.DistinguishedName -SmartcardLogonRequired $true
    }
}

Write-Host -NoNewLine "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

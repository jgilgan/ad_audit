#requires -version 5
<#
.SYNOPSIS
	Generate a report in HTML format about the chosen AD Options
	
.NOTES
	Version:		1.0
	Author:			Jan Gilgan
	Cration Date:	2021-10-10
	Change:			Initial version

.COMPONENT
	ActiveDirectory
	ServerManager
	GroupPolicy
	
.EXAMPLE
	powershell -ep bypass .\ad_audit.ps1 -allchecks
#>

[CmdletBinding()]
param(
    [switch]$gpo,
    [switch]$smb,
    [switch]$passwordpolicy,
    [switch]$hosts,
    [switch]$dcs,
    [switch]$users,
    [switch]$admins,
    [switch]$acl,
    [switch]$keeplogs,
	[string]$lang,
    [switch]$allchecks
)

if ($PSBoundParameters.Count -eq 0) {
$output = @()

$output += "-gpo\generate a separate report of GPOs"
$output += "-smb\show smb specific configuration"
$output += "-passwordpolicy\show the domain default password policy"
$output += "-hosts\list old servers and clients"
$output += "-dcs\list all domain controllers"
$output += "-users\list old / unused users"
$output += "-admins\list users that may have admin rights"
$output += "-acl\list all Domain-ACLs"
$output += "-keeplogs\keep old reports"
$output += "-lang\Report language | de = deutsch (default if not set)| en = english"
$output += "-allchecks\run all checks"
$output | ConvertFrom-String -PropertyNames Option, Beschreibung -Delimiter "\\"
}

#Set runtime variables
$defaultLang = "de"
$dt = get-date -format "dd.MM.yyyy hh-mm"
$currentUser = whoami
$currentHost = hostname
$daysInactive = 90
$Timestamp = [DateTime]::Today.AddDays(-$daysInactive)
$reportPath = "C:\report\"
$PowerShellVersion = ($PSVersionTable).PSVersion.Major
$OSVersion = ([System.Environment]::OSVersion.Version).Major
$tableWidth = "700px;"

#If Powershell major version is < 5 exit
if ($PowerShellVersion -lt 5) {
    Write-Host -foregroundcolor Yellow "[!!!] Please install Powershell Version 5 or above to run this script"
    exit
}

#If no language is specified, use the one provided inside script
if (-not $lang){
	$lang = $defaultLang
}

if ($PSBoundParameters.Count -gt 0) {
    if (Test-Path -Path $reportPath) {
        if (-not $keeplogs) {
        Write-Host -ForegroundColor yellow "report path does exist. Cleaning up old .html files"
        Get-ChildItem $reportPath *.html | foreach { Remove-Item -Path $_.FullName }
        }
    } else {
        Write-Host -ForegroundColor yellow "create report path"
        New-Item -ItemType Directory -Path $reportPath | Out-Null
    }
}

$DomainRole = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole


#check whether the script is run on a DC. If not -> exit
if (Get-Module -ListAvailable -Name ActiveDirectory){
	Import-Module ActiveDirectory
	} else {
		Write-Host "[!] ActiveDirectory is not installed on this machien. Aborting..." ; 
		exit
	}
if (Get-Module -ListAvailable -Name ServerManager){
	Import-Module ServerManager
	} else {
	Write-Host "[!] ServerManager is not available. Aborting..." ; 
	exit
	}
if (Get-Module -ListAvailable -Name GroupPolicy){
	Import-Module GroupPolicy
	} else {
	Write-Host "[!] GroupPolicy is not available. Aborting..." ; 
	exit
	}

#set domain specific variables
$DN = Get-ADDomain | select -expand distinguishedname
$Forest = Get-ADDomain | select -expand forest
$DomainLevel = (Get-ADDomain).domainMode
$ForestLevel = (Get-ADForest).ForestMode

#set language specific variables
if (($lang -eq "de") -or (-not $lang)) {
	$lastLogon_header = "<h2>Benutzer, welche seit $daysInactive Tagen nicht eingeloggt waren (seit $dt)</h2>"
	$disabledUsers_header = "<h2>Deaktivierte Benutzer</h2>"
	$passwordNotExpire_header = "<h2>Accounts bei denen die Passwörter nie ablaufen</h2>"
	$passwordLastSet_header = "<h2>Accounts, die seit 90 Tagen das Kennwort nicht geändert haben</h2>"
	$krbtgt_header =  "<h2>Datum, an dem das krbtgt Passwort zuletzt geändert wurde</h2>"
	
	$domAdmin_header = "<h2>Domänen-Admins</h2>"
	$orgAdmin_header = "<h2>Organisations-Admins</h2>"
	$adminUser_header = "<h2>Benutzer, die adm im Namen haben und administrative Rechte haben könnten</h2>"
	$admimGroup_header = "<h2>Gruppen, die adm im Namen haben und administrative Rechte haben könnten</h2>"
	
	$oldServer_header = "<h2>Alte Server Betriebssysteme</h2>"
	$oldDesktops_header = "<h2>Alte Desktop Betriebssysteme</h2>"

    $dcs_header = "<h2>Domänen-Controller</h2>"
	
	$acls_header = "<h2>ACLs Domänenweit</h2>"
	
	$netbios_header = "<h2>NetBios Einstellungen</h2>"
	$netbios_footer = "<p id='red'>0 / 1 = NetBios aktiviert (potenziell gefährlich!) </p><p id='blue'>2 = NetBios deaktiviert</p>"
	
	$passwordPolicy_header = "<h2>Domänen Passwortrichlinie (Standard)</h2>"
	
	$gpoOwner_header = "<h2>GPOs und deren Besitzer</h2>"

    $smb_header = "<h2>SMB Einstellungen</h2>"
    $smb1_disabled = "SMB1 ist deaktiviert"
    $smb1_enabled = "!!! SMB1 ist aktiviert !!!"
}

if ($lang -eq "en") {
	$lastLogon_header = "<h2>Users inactive for $daysInactive (since $dt)</h2>"
	$disabledUsers_header = "<h2>Disabled users</h2>"
	$passwordNotExpire_header = "<h2>Accounts with non-expiring passwords</h2>"
	$passwordLastSet_header = "<h2>Users who did not change passwords in 90 days</h2>"
	$krbtgt_header =  "<h2>Date on which krbtgt password was last set</h2>"
	
	$domAdmin_header = "<h2>Domain-Admins</h2>"
	$orgAdmin_header = "<h2>Organization-Admins</h2>"
	$adminUser_header = "<h2>Users who have 'adm' in their names and might be admins</h2>"
	$admimGroup_header = "<h2>Groups that have 'adm' in their names and might have administrative rights</h2>"
	
	$oldServer_header = "<h2>Old Server OperatingSystems</h2>"
	$oldDesktops_header = "<h2>Old Desktop OperatingSystems</h2>"

    $dcs_header = "<h2>Domain Controllers</h2>"
	
	$acls_header = "<h2>Domain ACLs</h2>"
	
	$netbios_header = "<h2>NetBios Settings (local machine)</h2>"
	$netbios_footer = "<p id='red'>0 / 1 = NetBios enabled (^potentially dangerous!) </p><p id='blue'>2 = NetBios disabled</p>"
	
	$passwordPolicy_header = "<h2>Default Password Policy</h2>"
	
	$gpoOwner_header = "<h2>GPOs and their owners</h2>"

    $smb_header = "<h2>SMB Settings</h2>"
    $smb1_disabled = "SMB1 is disabled"
    $smb1_enabled = "!!! SMB1 is enabled !!!"
}

if ($users -or $allchecks) {
    #find users that have not logged in in 90 days
    Write-Host -ForegroundColor yellow "checking users that are inactive for $daysInactive days"
    $lastLogon = Get-ADUser -Filter {((Enabled -eq $true) -and (LastLogonDate -lt $Timestamp))} -Properties LastLogonDate | select SamAccountName, Name, LastLogonDate | Sort-Object LastLogonDate 
    $lastLogonCount = $lastLogon.Count
    $lastLogon = $lastLogon | ConvertTo-Html -Fragment -PreContent $lastLogon_header -PostContent "<p id='tablefooter'>Total: $lastLogonCount</p><p><br></p>" | out-string

    #disabled users
    Write-Host -ForegroundColor yellow "checking disabled users"
    $disabledUsers = (Get-ADUser -Filter {((Enabled -eq $false))} | select SamAccountName, Name, LastLogonDate | Sort-Object LastLogonDate)
    $disabledUsersCount = $disabledUsers.Count
    $disabledUsers = $disabledUsers | ConvertTo-Html -Fragment -PreContent $disabledUsers_header -PostContent "<p id='tablefooter'>Total: $disabledUsersCount</p><p><br></p>" | out-string

    #accounts with non-expiring passwords
    Write-Host -ForegroundColor yellow "checking accounts with non-expiring passwords"
    $passwordNotExpire = Get-ADUser -Filter * -properties Name, PasswordNeverExpires | where { $_.passwordNeverExpires -eq "true" } | where {$_.enabled -eq "true"} 
    $passwordNotExpireCount = $passwordNotExpire.Count
    $passwordNotExpire = $passwordNotExpire | ConvertTo-Html -Fragment -Property Name,SamAccountName,PasswordNeverExpires -PreContent $passwordNotExpire_header -PostContent "<p id='tablefooter'>Total: $passwordNotExpireCount</p><p><br></p>"| out-string

    #accounts that did not change password in 90 days
    Write-Host -ForegroundColor yellow "checking accounts, that did not change password in 90 days"
    $passwordLastSet = Get-ADUser -Filter {PasswordLastSet -lt $Timestamp -and enabled -eq "true"} -properties PasswordLastSet | Select Name, PasswordLastSet
    $passwordLastSetCount = $passwordLastSet.Count
    $passwordLastSet = $passwordLastSet | ConvertTo-Html -Fragment -Property Name,SamAccountName,PasswordLastSet -PreContent $passwordLastSet_header -PostContent "<p id='tablefooter'>Total: $passwordLastSetCount</p><p><br></p>" | out-string

    #krbtgt last password change
    Write-Host -ForegroundColor yellow "checking date when krbtgt password was last changed"
    $krbtgtpass = (get-aduser -Filter {SamAccountName -eq "krbtgt"} -Properties PasswordLastSet) | Select Name, PasswordLastSet | ConvertTo-Html -Fragment -Property Name,PasswordLastSet -PreContent $krbtgt_header -PostContent "<br><p><hr align=left width=$tableWidth'</p><br>"| out-string
}

if ($admins -or $allchecks) {
    #domain-admins
    Write-Host -ForegroundColor yellow "checking domain-admins"
	if (($lang -eq "de") -or (-not $lang)){
		$DomAdmins = Get-ADGroupMember 'Domänen-Admins'
	}
	if ($lang -eq "en"){
		$DomAdmins = Get-ADGroupMember 'Domain-Admins'
	}
    $DomAdminCount = $DomAdmins.Count
    $DomAdmins = $DomAdmins | ConvertTo-Html -Fragment -Property Name,SamAccountName -PreContent $domAdmin_header -PostContent "<p id='tablefooter'>Total: $DomAdminCount</p><p><br></p>" | out-string
 
    #organization-admins
    Write-Host -ForegroundColor yellow "checking organization-admins"
	if (($lang -eq "de") -or (-not $lang)){
		$OrgAdmins = Get-ADGroupMember 'Organisations-Admins' 
	}
	if ($lang -eq "en"){
		$OrgAdmins = Get-ADGroupMember 'Organization-Admins'
	}
    $OrgAdminCount = $OrgAdmins.Count 
    $OrgAdmins = $OrgAdmins | ConvertTo-Html -Fragment -Property Name,SamAccountName -PreContent $orgAdmin_header -PostContent "<p id='tablefooter'>Total: $OrgAdminCount</p><p><br></p>" | out-string

    #admin users
    Write-Host -ForegroundColor yellow "checking users, that contain 'adm' and might be admins"
    $adminUser = Get-ADUser -Filter {name -like "*adm*"}
    $adminUserCount = ($adminUser.SamAccountName).Count
    $adminUser = $adminUser | ConvertTo-Html -Fragment -Property Name -PreContent $adminUser_header -PostContent "<p id='tablefooter'>Total: $adminUserCount</p><p><br></p>" | out-string

    #admin groups
    Write-Host -ForegroundColor yellow "checking groups, that contain 'adm' and might have admin rights"
    $adminGroups = Get-ADGroup -Filter {name -like "*adm*"}
    $adminGroupsCount = $adminGroups.Count
    $adminGroups = $adminGroups | ConvertTo-Html -Fragment -Property Name -PreContent $admimGroup_header -PostContent "<p id='tablefooter'>Total: $adminGroupsCount</p><p><br><hr align=left width=$tableWidth'</p><br>" | out-string
}

if ($hosts -or $allchecks) {
    #old servers
    Write-Host -ForegroundColor yellow "checking old servers (Server 2003 / Server 2008)"
    $oldServers = Get-ADComputer -Filter { Operatingsystem -like "*Server*" -and ((Operatingsystem -like "*2003*") -or (Operatingsystem -like "*2008*")) -and enabled -eq "true" } `
    -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address |
    Sort-Object -Property Operatingsystem |
    Select-Object -Property Name,Operatingsystem,OperatingSystemVersion,IPv4Address
    $oldServersCount = $oldServers.Count
    $oldServers = $oldServers | ConvertTo-Html -Fragment -PreContent $oldServer_header -PostContent "<p id='tablefooter'>Total: $oldServersCount</p><p><br></p>" | out-string

    #old desktops
    Write-Host -ForegroundColor yellow "checking old desktops (7 / Vista / XP / 2000)"
    $oldDesktops =  Get-ADComputer -Filter { Operatingsystem -like "*XP*" -and enabled -eq "true" -or OperatingSystem -Like "*2000*" -and enabled -eq "true" -or OperatingSystem -like "*Windows 7*" -and enabled -eq "true" -or OperatingSystem -like '*vista*' -and Enabled -eq "true"} `
    -Properties Name,Operatingsystem,OperatingSystemVersion,IPv4Address |
    Sort-Object -Property Operatingsystem |
    Select-Object -Property Name,Operatingsystem,OperatingSystemVersion,IPv4Address 
    $oldDesktopsCount = $oldDesktops.Count
    $oldDesktops = $oldDesktops | ConvertTo-Html -Fragment -PreContent $oldDesktops_header -PostContent "<p id='tablefooter'>Total: $oldDesktopsCount</p><p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
}

if ($dcs -or $allchecks) {
    Write-Host -ForegroundColor yellow "checking domain controllers"
    $domaincontrollers = Get-ADDomainController -Filter * | Select Domain,Name,IPv4Address,IsGlobalCatalog,Site,OperatingSystem
    $domaincontrollersCount = ($domaincontrollers.Name).Count
    $domaincontrollers = $domaincontrollers | ConvertTo-Html -Fragment -PreContent $dcs_header -PostContent "<p id='tablefooter'>Total: $domaincontrollersCount</p><p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
}

if ($acl -or $allchecks) {
    #get acls
    Write-Host -ForegroundColor yellow "checking acls"
    $ACLs = (Get-ACL AD:\$DN).Access | ConvertTo-Html -Fragment -Property IdentityReference,ActiveDirectoryRights -PreContent $acls_header -PostContent "<p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
}

if ($passwordpolicy -or $allchecks) {
    #default password policy
    Write-Host -ForegroundColor yellow "checking default password policy"
    $PasswortRichtlinie_part1 = Get-ADDefaultDomainPasswordPolicy | ConvertTo-Html -Fragment -Property ComplexityEnabled,DistinguishedName,LockoutDuration -PreContent $passwordPolicy_header -PostContent "<br>" | out-string
    $PasswortRichtlinie_part2 = Get-ADDefaultDomainPasswordPolicy | ConvertTo-Html -Fragment -Property LockoutObservationWindow,LockoutThreshold,MaxPasswordAge -PostContent "<br>" | out-string
    $PasswortRichtlinie_part3 = Get-ADDefaultDomainPasswordPolicy | ConvertTo-Html -Fragment -Property MinPasswordAge,MinPasswordLength,PasswordHistoryCount -PostContent "<p><br><hr align=left width=$tableWidth'</p><p><br></p>"| out-string
    $PasswortRichtlinie = $PasswortRichtlinie_part1 + $PasswortRichtlinie_part2 + $PasswortRichtlinie_part3
}

if ($gpo -or $allchecks) {
    #check gpos / owners
    Write-Host -ForegroundColor yellow "checking GPO / GPO owner"
    $GPOs = Get-GPO -All | ConvertTo-Html -Fragment -Property DisplayName,CreationTime,ModificationTime,Owner -PreContent $gpoOwner_header -PostContent "<p><hr align=left width=$tableWidth'</p><p><br></p>"| out-string

    #separate, full gpo report
    Write-Host -ForegroundColor yellow "creating full gpo report"
    Get-GPOReport -All -ReportType HTML -Path $reportPath\GPO_Report_$dt.html
}

if ($smb -or $allchecks) {
    #check smb settings 
    Write-Host -ForegroundColor yellow "checking smb settings"

    if ($OSVersion -eq 6) {
        #Server 2008, 2012 R2
        $check_smb1 = (Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}).SMB1
        $check_smb2 = (Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath}).SMB2
        if ($check_smb1 -eq 0) {
            $smb1 = "$smb1_disabled#" | ConvertFrom-String -PropertyNames "SMB" -Delimiter "#" | ConvertTo-Html -Fragment -Property "SMB" -PreContent $smb_header -PostContent "<p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
		}
        elseif ((-not $check_smb1) -or (($check_smb1 -eq 1) -or ($check_smb2 -eq 0))) {
            $smb1 = "$smb1_enabled#" | ConvertFrom-String -PropertyNames "SMB" -Delimiter "#" | ConvertTo-Html -Fragment -Property "SMB" -PreContent $smb_header -PostContent "<p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
            $smb1 = $smb1 -replace "<td>$smb1_enabled</td>","<td class='red'><b>$smb1_enabled</b></td>"
        }
    }
    if ($OSVersion -eq 10) {
        #Server 2019
        $check_smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).state
        #check_smb2 not in use for now
        $check_smb2 = (Get-SmbServerConfiguration | Select -ExpandProperty EnableSMB2Protocol)
        if ($check_smb1 -eq "disabled") {
            $smb1 = "$smb1_disabled#" | ConvertFrom-String -PropertyNames "SMB" -Delimiter "#" | ConvertTo-Html -Fragment -Property "SMB" -PreContent $smb_header -PostContent "<p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
        }
        elseif ($check_smb1 -eq "enabled") {
            $smb1 = "$smb1_enabled#" | ConvertFrom-String -PropertyNames "SMB" -Delimiter "#" | ConvertTo-Html -Fragment -Property "SMB" -PreContent $smb_header -PostContent "<p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
            $smb1 = $smb1 -replace "<td>$smb1_enabled</td>","<td class='red'><b>$smb1_enabled</b></td>"
        }
    }
}

if ($allchecks) {
#netbios status
Write-Host -ForegroundColor yellow "checking netbios status"
$NetBiosregkey = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
$NetBios = Get-ChildItem $NetBiosregkey |foreach {Get-ItemProperty -Path "$NetBiosregkey\$($_.pschildname)" -Name NetbiosOptions } | ConvertTo-Html -Fragment -Property PSPath,NetbiosOptions -PreContent $netbios_header -PostContent "$netbios_footer <p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
$NetBios = $NetBios -replace "<td>0</td>","<td class='red'><b>0</b></td>"
$NetBios = $NetBios -replace "<td>1</td>","<td class='red'><b>1</b></td>"

#LLMNR status
Write-Host -ForegroundColor yellow "checking llmnr status"
$LLMNRregkey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT"
try { 
    if ((Get-ItemProperty -Path "$LLMNRregkey\DNSClient\" -ErrorAction Stop | Select-Object -ExpandProperty EnableMulticast) -eq 0){
        Write-Host "LLMNR is disabled" } 
    else { 
		if (($lang -eq "de") -or (-not $lang)){
			$LLMNRStatus = "!!! LLMNR ist aktiviert !!!#" | ConvertFrom-String -PropertyNames "LLMNR-Status" -Delimiter "#" | ConvertTo-Html -Fragment -Property "LLMNR-Status" -PreContent "<h2>LLMNR (lokale Maschine)</h2>" -PostContent "<p id='red'>Vermutlich ist LLMNR Domänenweit aktiviert</p><p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
		}
		if ($lang -eq "en"){
			$LLMNRStatus = "!!! LLMNR is enabled !!!#" | ConvertFrom-String -PropertyNames "LLMNR-Status" -Delimiter "#" | ConvertTo-Html -Fragment -Property "LLMNR-Status" -PreContent "<h2>LLMNR (local machine)</h2>" -PostContent "<p id='red'>Probably LLMNR is enabled in the entire domain</p><p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
		}
    }
} 
catch { 
    if (($lang -eq "de") -or (-not $lang)){
		$LLMNRStatus = "!!! LLMNR ist aktiviert !!!#" | ConvertFrom-String -PropertyNames "LLMNR-Status" -Delimiter "#" | ConvertTo-Html -Fragment -Property "LLMNR-Status" -PreContent "<h2>LLMNR (lokale Maschine)</h2>" -PostContent "<p id='red'>Vermutlich ist LLMNR Domänenweit aktiviert</p><p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
	}
	if ($lang -eq "en"){
		$LLMNRStatus = "!!! LLMNR is enabled !!!#" | ConvertFrom-String -PropertyNames "LLMNR-Status" -Delimiter "#" | ConvertTo-Html -Fragment -Property "LLMNR-Status" -PreContent "<h2>LLMNR (local machine)</h2>" -PostContent "<p id='red'>Probably LLMNR is enabled in the entire domain</p><p><hr align=left width=$tableWidth'</p><p><br></p>" | out-string
	}
}
}

$header = @"
<style>

    h1 {
        font-family: Arial;
        color: #FFAB00;
        font-size: 28px;
    }
    
    h2 {
        font-family: Arial;
        color: #009900;
		font-weight: bold;
        font-size: 16px;
    }
     
   table {
        width: $tableWidth;
        max-width: 2400px;
		font-size: 12px;
		border: 0px; 
		font-family: Arial;
	} 
	
    td {
        width: $tableWidth; 
        max-width: $tableWidth;
		padding: 4px;
		margin: 0px;
		border: 1;
	}
	
    th {
        background: #406385;
        color: #fff;
        font-size: 11px;
        padding: 12px 16px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #e0e0e0;
    }

    #red {
        font-family: Arial;
        color: #ff3300;
        font-size: 12px;
    }
	
	#blue {
        font-family: Arial;
        color: #0033ff;
        font-size: 12px;
    }
    #tablefooter {
        font-family: Arial;
        font-size: 12px;
        font-weight: bold;
    }
	
	.red {
		color: #ff0000;
	}

@media print {
   table {
		width: 100%;
        border: 1pt solid #000000;
        border-collapse: collapse; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	td {
		padding: 4px;
		margin: 0px;
		border: 1pt solid #000000;
	}
	
	tr {
		border: 1pt solid #000000;
	}
	
    th {
        padding: 10px 15px;
        vertical-align: middle;
		border: 1pt solid #000000;
	}
}
</style>
"@

if ($PSBoundParameters.Count -gt 0) {
    if (($lang -eq "de") -or (-not $lang)) {
        $ReportTitel = "<h1>Schnell-Übersicht über die Domain $Forest</h1>"
        $Report = ConvertTo-Html -Body "$ReportTitel $lastLogon $disabledUsers $passwordNotExpire $passwordLastSet $krbtgtpass $DomAdmins $OrgAdmins $adminUser $adminGroups $oldServers $oldDesktops $domaincontrollers $PasswortRichtlinie $smb1 $GPOs $NetBios $LLMNRStatus $ACLs" -Title "Active Directory Mini-Audit Report $dt" -Head $header -PostContent "<p id='red'>Erstellungsdatum: $(date) - ausgeführt als Benutzer $currentUser auf $currentHost<p>"
        $Report | Out-File $reportPath\AD_Report_$dt.html
    }

    if ($lang -eq "en") {
        $ReportTitel = "<h1>Quick Overview for Domain $Forest</h1>"
        $Report = ConvertTo-Html -Body "$ReportTitel $lastLogon $disabledUsers $passwordNotExpire $passwordLastSet $krbtgtpass $DomAdmins $OrgAdmins $adminUser $adminGroups $oldServers $oldDesktops $domaincontrollers $PasswortRichtlinie $smb1 $GPOs $NetBios $LLMNRStatus $ACLs" -Title "Active Directory Mini-Audit Report $dt" -Head $header -PostContent "<p id='red'>Create-Date: $(date) - run as user $currentUser on $currentHost<p>"
        $Report | Out-File $reportPath\AD_Report_$dt.html
    }
}


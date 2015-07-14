<#
Written by: Tyler Applebaum
Modified by: Andy Niel
Notes: In order for the file copy to work, Enable-WSManCredSSP must be configured in your domain. If you choose not to do this, you can use the Autocopier.ps1 to pre-stage the DTClient file on the target computers. You will also need to remove the Authentication CredSSP from the Invoke-Command statement as well. Check on the GPO to configure WSMAN trusted hosts if you run into issues.
$Rev =  "v3.6 7 July 2015"
#>

[CmdletBinding(DefaultParameterSetName = "Set1")]
  Param(
  [Parameter(parametersetname="Set1", HelpMessage="Specify the path to the list of computers (C:\Scripts\list.txt)")]
	[Alias("l")]
	[string]$Complist,

  [Parameter(parametersetname="Set2", HelpMessage="Specify the Get-ADComputer name filter (* for wildcard")]
	[Alias("f")]
	[string]$Filter,

  [Parameter(HelpMessage="Switch to INSTALL the NEW DTclient")]
	[Alias("in")]
	[switch] $INew,

  [Parameter(HelpMessage="Switch to UNINSTALL the OLD DTclient")]
	[Alias("uo")]
	[switch] $UOld,

  [Parameter(HelpMessage="Switch to UNINSTALL the NEW DTclient")]
	[Alias("un")]
	[switch] $UNew,

  [Parameter(HelpMessage="Switch to INSTALL the OLD DTclient")]
	[Alias("io")]
	[switch] $IOld,

  [Parameter(HelpMessage="Specify \\server\share for NEW DTClient.msi")]
	[Alias("so")]
	[string]$ShareN = "\\rw-p-netadmin1\Staging\Desktop",

  [Parameter(HelpMessage="Specify \\server\share\ for OLD DTClient.msi")]
	[Alias("sn")]
	[string]$ShareO = "\\rw-p-netadmin1\Staging\OldDT"
	)
	
Write-Host @'
    ____  ______________    ___________   ________
   / __ \/_  __/ ____/ /   /  _/ ____/ | / /_  __/
  / / / / / / / /   / /    / // __/ /  |/ / / /
 / /_/ / / / / /___/ /____/ // /___/ /|  / / /
/_____/ /_/  \____/_____/___/_____/_/ |_/ /_/

'@ -fo green
Write-host "Usage: DTClientUpdate.ps1 -l / -f / -uo / -in / -un / -io / -so / -sn "-fo white
Write-host @'

-l <Path_to_computer_list.txt>
-f <Get-ADComputer filter>
-uo (Uninstalls OLD DTClient)
-in (Installs NEW DTClient)
-un (Uninstalls NEW DTClient)
-io (Installs OLD DTClient)
-so <\\server\share for OLD DTClient.msi>
-sn <\\server\share for NEW DTClient.msi>

'@ -fo yellow
Write-host @'
Note: Running without install parameters (-uo,-in,-un,-io)
generates DTClientReport.csv based on -l or -f parameters.

'@ -fo white

Function TestFileLock {
	## Attempts to open a file and trap the resulting error if the file is already open/locked
    Param ([string]$FilePath = "$Env:UserProfile\Desktop\DTClientReport.csv")
    $Filelocked = $False
    $FileInfo = New-Object System.IO.FileInfo $FilePath
    Trap {
        Set-Variable -name FileLocked -Value $True -Scope 1
        Continue
    }
    $FileStream = $FileInfo.Open( [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None )
    If ($FileStream){
        $FileStream.Close()
    }
    $filelocked
}#end TestFileLock

Function script:Input {
	If ($Complist){
	#Get content of file specified, trim any trailing spaces and blank lines
	$script:Computers = gc ($Complist) | where {$_ -notlike $null } | foreach { $_.trim() }
	}
	Elseif ($Filter) {
		If (!(Get-Module ActiveDirectory)) {
		Import-Module ActiveDirectory
		} #include AD module
	#Filter out AD computer objects with ESX in the name
	$script:Computers = Get-ADComputer -Filter {SamAccountName -notlike "*esx*" -AND Name -Like $Filter} | select -ExpandProperty Name | sort
	}
}#end Input

Function script:PingTest {
$script:TestedComps = @()
$script:BadComps = @()
	foreach ($WS in $Computers){
	$i++
		If (Test-WSMan -auth Default -computername $WS 2>$Null){
		$script:TestedComps += "$WS.$env:userdnsdomain" #essential to append the FQDN with WSManCredSSP
		}
		Else {
		Write-Output "Cannot connect to $WS"
		$script:BadComps += $WS
		}
	Write-Progress -Activity "Testing connectivity" -status "Tested connection to computer $i of $($computers.count)" -percentComplete ($i / $computers.length*100)
	}#end foreach
	$BadComps | Out-File $env:userprofile\Desktop\WSManBroken.txt
}#end PingTest

Function script:Duration {
$Time = $((Get-Date)-$date)
	If ($Time.totalseconds -lt 60) {
	$dur = "{0:N3}" -f $Time.totalseconds
	Write-Host "`r`nOperation completed in $dur seconds.`r`nDTClientReport.csv saved to Desktop.`r`n" -fo DarkGray
	}
	Elseif ($Time.totalminutes -gt 1) {
	$dur = "{0:N3}" -f $Time.totalminutes
	Write-Host "`r`nOperation completed in $dur minutes.`r`nDTClientReport.csv saved to Desktop.`r`n" -fo DarkGray
	}
}#end Duration

$Scriptblock = {
param ($INew,$UNew,$IOld,$UOld,$ShareN,$ShareO)
$date = get-date

	Function script:Registry {
		If (Test-Path "C:\Program Files (x86)"){
		$Platform = "x64"
		$Progs = "C:\Program Files (x86)"
		$UninstallKey="SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
		}
		Else {
		$Platform = "x86"
		$Progs = "C:\Program Files"
		$UninstallKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
		}
		$task = "Install Report"
		$PathNew = "$Progs\Fiserv\Desktop\13.1.6"
		$PathOld = "$Progs\Fiserv\Desktop\13.1.2"

		If ((Test-Path "HKLM:\$UninstallKey\{9B9618B1-6C26-4563-9B6F-7C406D03D3A7}") -AND (Test-Path $PathNew)){
		$IsInstalled = (((gci "$PathNew\CBSDesktop.ocx").versioninfo).productversion) #version check
		}
		Elseif ((Test-Path "HKLM:\$UninstallKey\{9B9618B1-6C26-4563-9B6F-7C406D03D3A7}") -AND (Test-Path $PathOld)){
		$IsInstalled = (((gci "$PathOld\CBSDesktop.ocx").versioninfo).productversion) #version check
		}
		Else {
		$IsInstalled = "None"
		}
	}#End Registry

	Function InstallN {
		$MSI = "$ShareN\DTclient.msi"
		$task = "Install NEW"
		If (!(Test-Path "C:\Windows\Temp\dtclient.msi") -AND (test-path $MSI)){
		Copy-Item -Path "$MSI" -Destination "C:\Windows\Temp" -force
		}
		Write-Host "Installing NEW client on $env:computername" -fore DarkGray
		$Install = cmd /c MsiExec.exe /qn /i "C:\Windows\Temp\dtclient.msi"
		If ($LastExitCode -eq '0'){
		$Inst = "TRUE"
		Write-Host "NEW client successfully installed on $env:computername!" -fo green
		}
		Else {
		$Inst = $Install
		Write-Host "Install results: $Install"
		Write-Host $LastExitCode -fore Red #Debugging purposes
		}
	}#End InstallDT

	Function InstallO {
		$MSI = "$ShareO\DTclient.msi"
		$task = "Install OLD"
		If (!(Test-Path "C:\Windows\Temp\OldDT\dtclient.msi") -AND (test-path $MSI)){
		Copy-Item -path "$MSI" -destination (new-item -Path "C:\Windows\Temp" -name "OldDT" -type directory -force)
		}
		Write-Host "Installing OLD client on $env:computername" -fore DarkGray
		$Install = cmd /c MsiExec.exe /qn /i "C:\Windows\Temp\OldDT\dtclient.msi"
		If ($LastExitCode -eq '0'){
		$Inst = "TRUE"
		Write-Host "OLD client successfully installed on $env:computername!" -fo green
		}
		Else {
		$Inst = $Install
		Write-Host "Install results: $Install"
		Write-Host $LastExitCode -fore Red #Debugging purposes
		}
	}#End InstallDT

    Function UninstallN {
		$MSI = "$ShareN\DTclient.msi"
		$task = "Uninstall NEW"
		If (!(Test-Path "C:\Windows\Temp\dtclient.msi") -AND (test-path $MSI)){
		Copy-Item -path "$MSI" -destination "C:\Windows\Temp" -force
		}
		Write-Host "Removing NEW client on $env:computername" -fore DarkGray
		$Uninstall = cmd /c MsiExec.exe /qn /x "C:\Windows\Temp\dtclient.msi"
		If ($LastExitCode -eq '0'){
		$Uninst = "TRUE"
		Write-Host "NEW client successfully removed on $env:computername!" -fo green
		}
		Else {
		$Uninst = $Uninstall
		Write-Host "Uninstall results: $Uninstall"
		Write-Host $LastExitCode -fore Red #Debugging purposes
		}
	}#End UninstDT

	Function UninstallO {
		$MSI = "$ShareO\DTclient.msi"
		$task = "Uninstall OLD"
		If (!(Test-Path "C:\Windows\Temp\OldDT\dtclient.msi") -AND (test-path $MSI)){
		Copy-Item -path "$MSI" -destination (new-item -Path "C:\Windows\Temp" -name "OldDT" -type directory -force)
		}
		Write-Host "Removing OLD client on $env:computername" -fore DarkGray
		$Uninstall = cmd /c MsiExec.exe /qn /x "C:\Windows\Temp\OldDT\dtclient.msi"
		If ($LastExitCode -eq '0'){
		$Uninst = "TRUE"
		Write-Host "OLD client successfully removed on $env:computername!" -fo green
		}
		Else {
		$Uninst = $Uninstall
		Write-Host "Uninstall results: $Uninstall"
		Write-Host $LastExitCode -fore Red #Debugging purposes
		}
	}#End UninstDT

	. Registry #Call Registry function
	If ($INew){
	. InstallN #Call InstallN function
	}
	If ($IOld){
	. InstallO #Call InstallO function
	}
	If ($UNew){
	. UninstallN #Call UninstallN function
	}
	If ($UOld){
	. UninstallO #Call UninstallO function
	}

	$Properties = @{
	Task = $Task
	Computer = $Env:ComputerName
	ExitCode = $LastExitCode
	Platform = $Platform
	InstallSuccess = $Inst
	UninstallSuccess = $Uninst
	AlreadyInstalled = $IsInstalled
	}

	$Obj = New-Object -TypeName PSObject -Property $properties
	$Results+= $Obj
	Write-Output $Results
} #end scriptblock

$AllResults = @()
$i = 0
$date = get-date
$Cred = Get-Credential $env:userdomain\$env:username
If (. TestFileLock){
Write-host "*** DTClientReport.csv file is locked, pleas close it and re-run script. ***`n`r" -fo magenta
[console]::beep(400,200)
Exit
}
if ((!$complist) -and (!$filter)){
[console]::beep(300,200)
write-host "*** This script must be run with -l or -f parameter! ***`n`r" -fo magenta
exit
}
. Input #Call input function
. Pingtest #Call PingTest function
write-host "Performing operations on $filter$complist..." -fo cyan
$Results = Invoke-Command -ComputerName $TestedComps -Scriptblock ${Scriptblock} -ArgumentList @($INew,$UNew,$IOld,$UOld,$ShareN,$ShareO) -Credential $Cred -Authentication CredSSP
$AllResults += $Results #Add result to array
. Duration #Call duration function
$AllResults | Select Task,Computer,Platform,AlreadyInstalled,InstallSuccess,UninstallSuccess,ExitCode | Sort Computer | Export-CSV -Path "$Env:UserProfile\Desktop\DTClientReport.csv" -notypeinformation

<#
Written by: Tyler Applebaum
Notes: In order for the file copy to work, Enable-WSManCredSSP must be configured in your domain. If you choose not to do this, you can use the Autocopier.ps1 to pre-stage the DTClient file on the target computers. You will also need to remove the Authentication CredSSP from the Invoke-Command statement as well. Check on the GPO to configure WSMAN trusted hosts if you run into issues.

$Rev =  "v3.1 10 Oct 2014"

Usage: DTClient-All.ps1 -l <Path_to_computer_list.txt> -f <Get-ADComputer filter (Can use single name too)> -v <12 or 13 or 14> -i (Installs DTClient) -u (Uninstalls DTClient) 
If ran with no parameters, the script will generate a report on the workstations and versions of DTClient it encounters. 

Current bugs: If DTClient 13 is present, DTClient 12 will not be checked for. Need to turn into an array to check for all versions, like in Get-Java.ps1.
#>
[CmdletBinding(DefaultParameterSetName = "Set1")]
    Param(
        [Parameter(mandatory=$true, parametersetname="Set1", HelpMessage="Specify the path to the list of computer names (C:\Scripts\list.txt)")]
		[Alias("l")]
        [string]$Complist,

        [Parameter(mandatory=$true, parametersetname="Set2", HelpMessage="Specify the Get-ADComputer name filter to apply (Use * for wildcard")]
		[Alias("f")]
        [string]$Filter,
		
		[Parameter (Mandatory=$false)]
		[ValidateSet('12','13','14')]
		[Alias("v")]
		[int] $script:Version,
		
		[Parameter(Mandatory=$false)]
		[Alias("i")]
		[switch] $Inst,
		
		[Parameter(Mandatory=$false)]
		[Alias("u")]
		[switch] $Uninst,
		
        [Parameter(mandatory=$false, HelpMessage="Specify the server where the DTClient.msi can be found")]
		[Alias("Srv")]
        [string]$Server = "\\BOS-Shares02",

        [Parameter(mandatory=$false, HelpMessage="Specify the path to the DTClient.msi file")]
		[Alias("Sh")]
        [string]$Share = "GroupShares\ITNetwork\DesktopClient\$Version"	
	)
	
Write-Host @'
    ____  ______________    ___________   ________
   / __ \/_  __/ ____/ /   /  _/ ____/ | / /_  __/
  / / / / / / / /   / /    / // __/ /  |/ / / /   
 / /_/ / / / / /___/ /____/ // /___/ /|  / / /    
/_____/ /_/  \____/_____/___/_____/_/ |_/ /_/     
  
'@ -fo green

Function TestFileLock {
    ## Attempts to open a file and trap the resulting error if the file is already open/locked
    Param ([string]$FilePath = "$Env:UserProfile\Desktop\DesktopClientResults.csv")
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
	Write-Host "Script completed in $dur seconds" -fo DarkGray
	}
	Elseif ($Time.totalminutes -gt 1) {
	$dur = "{0:N3}" -f $Time.totalminutes
	Write-Host "Script completed in $dur minutes" -fo DarkGray
	}
}#end Duration

$Scriptblock = {
param ($Version,$Inst,$Uninst,$Server,$Share)
$date = get-date
	
	Function script:ValidateMSI {
	Write-Host $Server\$Share\DTClient$Version.msi -fo green
	$MSI = Test-Path "$Server\$Share\DTClient$Version.msi"
	}
	
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
		
		$Path13 = "$Progs\Fiserv"
		$Path12 = "$Progs\FiservCBS"
		
		If (Test-Path $Path13){
		$DT13 = (((gci "$Path13\Desktop\13.1.2\CBSDesktop.ocx").versioninfo).productversion) #version check
		}
		Elseif (Test-Path $Path12){
		$DT12 = (((gci "$Path12\Desktop\12.1.2\CBSDesktop.ocx").versioninfo).productversion) #version check
		}
		
		If ((Test-Path "HKLM:\$UninstallKey\{9B9618B1-6C26-4563-9B6F-7C406D03D3A7}") -AND (Test-Path $Path13)){
		$IsInstalled = "True"
		}
		Else {
		$IsInstalled = "False"
		}
	}#End Registry

	Function InstallDT {
		. ValidateMSI
		If (!(Test-Path "C:\Windows\Temp\dtclient$Version.msi") -AND ($MSI)){
		Copy-Item -Path "$Server\$Share\dtclient$Version.msi" -Destination "C:\Windows\Temp"
		}
		Write-Host "Installing DTClient $Version on $env:computername" -fore DarkGray
		$Install = cmd /c MsiExec.exe /qn /i "C:\Windows\Temp\dtclient$Version.msi"
		If ($LastExitCode -eq '0'){
		$Inst = "TRUE"
		Write-Host "DTClient $Version successfully installed on $env:computername!" -fo green
		}
		Else {
		$Inst = $Install
		Write-Host "Install results: $Install"
		Write-Host $LastExitCode -fore Red #Debugging purposes
		}		
	}#End InstallDT
	
		Function UninstDT {
		. ValidateMSI
		If (!(Test-Path "C:\Windows\Temp\dtclient$Version.msi") -AND ($MSI)){
		Copy-Item -Path "$Server\$Share\dtclient$Version.msi" -Destination "C:\Windows\Temp"
		}
		Write-Host "Removing DTClient $Version on $env:computername" -fore DarkGray
		$Uninstall = cmd /c MsiExec.exe /qn /x "C:\Windows\Temp\dtclient$Version.msi"
		If ($LastExitCode -eq '0'){
		$Uninst = "TRUE"
		Write-Host "DTClient $Version successfully removed on $env:computername!" -fo green
		}
		Else {
		$Uninst = $Uninstall
		Write-Host "Uninstall results: $Uninstall"
		Write-Host $LastExitCode -fore Red #Debugging purposes
		}		
	}#End UninstDT
	
	. Registry #Call Registry function
	If ($Inst){
	. InstallDT #Call InstallDT function
	}
	If ($Uninst){
	. UninstDT #Call UninstDT function
	}
	
	$Properties = @{
	Computer = $Env:ComputerName
	ExitCode = $LastExitCode
	Platform = $Platform
	InstallSuccessful = $Inst
	UninstallSuccessful = $Uninst
	DT13Installed = $IsInstalled
	DT13Ver = $DT13
	DT12Ver = $DT12
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
Write-Error "The file $Env:UserProfile\Desktop\DesktopClientResults.csv is currently open. Close the file and re-run the script."
Exit
}
. Input #Call input function
. Pingtest #Call PingTest function
$Results = Invoke-Command -ComputerName $TestedComps -Scriptblock ${Scriptblock} -ArgumentList @($Version,$Inst,$Uninst,$Server,$Share) -Credential $Cred -Authentication CredSSP
$AllResults += $Results #Add result to array
. Duration #Call duration function
$AllResults | Select Computer,Platform,DT13Installed,ExitCode,InstallSuccessful,UninstallSuccessful,DT13Ver,DT12Ver | Sort Computer | Export-CSV -Path "$Env:UserProfile\Desktop\DesktopClientResults.csv" -notypeinformation
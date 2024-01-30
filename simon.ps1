#STEP0
#Collect Variable Hosts from SE Lab machine. Collects characters at position 4-6.  Add a date in names so we dont get duplicates in SE cids
   
$SE_Initials = $env:computername.split("-")[1]
$Mydate=Get-Date -Format "MMdd"
$DomainName = $SE_Initials + $Mydate + ".com"
#THIS IS THE ONLY LINE YOU NEED TO ADAPT EVERYTIME YOU RUN THAT SCRIPT
$counter="A"
  
#STEP1
#Download and Extract PSexec
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 'pstools.zip'
Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools"
Move-Item -Path "$env:TEMP\pstools\psexec64.exe" -Destination "C:\Windows\System32\psexec64.exe"
Remove-Item -Path "$env:TEMP\pstools" -Recurse
  
#STEP2
#Enable PS Remoting on Lab machines
psexec64.exe \\172.17.0.34 -accepteula -u administrator -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
#Enable PS Remoting on Lab machines
psexec64.exe \\172.17.0.26 -u demo -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
psexec64.exe \\172.17.0.30 -u demo -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
psexec64.exe \\172.17.0.29 -u badguy -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Enable-PSRemoting -Force"
  
#STEP3
#Rename All Machines to include an extra number (also to avoid duplicates in SE UIs, DC machine is renamed with W19 instead of W2019 else the computername is too long)
$computerBL="SE-"+ $SE_Initials +""+ $counter +"-W10-BL"
$computerDT="SE-"+ $SE_Initials +""+ $counter +"-W10-DT"
$computerCO="SE-"+ $SE_Initials +""+ $counter +"-W10-CO"
$computerDC="SE-"+ $SE_Initials +""+ $counter +"-W19-DT"
psexec64.exe \\172.17.0.30 -accepteula -u demo -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Rename-Computer -NewName $computerBL -Force -Restart"
psexec64.exe \\172.17.0.26 -u demo -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Rename-Computer -NewName $computerDT -Force -Restart"
psexec64.exe \\172.17.0.29 -u badguy -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Rename-Computer -NewName $computerCO -Force -Restart"
psexec64.exe \\172.17.0.34 -u administrator -p Crowdstrike2017! -i -w c:\ -d -h powershell.exe "Rename-Computer -NewName $computerDC -Force -Restart"
  
#STEP4
#Pause script for 4 minutes to wait for machines to reboot after changing names
$x = 4*60
$length = $x / 100
while($x -gt 0) {
$min = [int](([string]($x/60)).split('.')[0])
$text = " " + $min + " minutes " + ($x % 60) + " seconds left"
Write-Progress "Pausing Script while waiting for reboot to complete" -status $text -perc ($x/$length)
start-sleep -s 1
$x--
}
   
   
#STEP5
#Update RDP Jumpbox host file for W2019 hostname and IP
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "172.17.0.34`t$computerDC"
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "172.17.0.34`t$computerDC.$DomainName"
   
   
#STEP6
#Update local Trusted host list
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$computerDC,$computerDC.$DomainName" -Force
   
#STEP7
#Update remote trusted host list
psexec64.exe \\172.17.0.34 -u administrator -p Crowdstrike2017! -i -h -d powershell.exe "Set-Item WSMan:\localhost\Client\TrustedHosts -value * -force"
   
 
#STEP8
#Active Directory Setup
$AD_Setup = {Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
Import-Module ActiveDirectory
$Mydate=Get-Date -Format "MMdd"
$SE_Initials_2 = $env:computername.split("-")[1]
$SE_Initials_2=$SE_Initials_2.Substring(0,$SE_Initials_2.Length-1)
$DomainName = $SE_Initials_2 +  $Mydate + ".com"
$DomainShort=$SE_Initials_2 +  $Mydate
$Password = ConvertTo-SecureString -AsPlainText -String Crowdstrike2017! -Force
Install-ADDSForest -DomainName "$DomainName" -SafeModeAdministratorPassword $Password ` -DomainNetbiosName $DomainShort  -DomainMode Win2012R2 -ForestMode Win2012R2 -DatabasePath "%SYSTEMROOT%\NTDS" ` -LogPath "%SYSTEMROOT%\NTDS" -SysvolPath "%SYSTEMROOT%\SYSVOL" -InstallDns -Force
}
 
#STEP9
$creduser = "administrator"
$credpass = convertto-securestring -String "Crowdstrike2017!" -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $creduser,$credpass
Invoke-Command -Computer $computerDC -Script $AD_Setup –credential $cred
   
#STEP10
#Pause script for 10 minutes to wait for AD Machine reboot to complete
$x = 8*60
$length = $x / 100
while($x -gt 0) {
$min = [int](([string]($x/60)).split('.')[0])
$text = " " + $min + " minutes " + ($x % 60) + " seconds left"
Write-Progress "Pausing Script while waiting for reboot to complete" -status $text -perc ($x/$length)
start-sleep -s 1
$x--
}
   
#STEP11
#Update Lab machines to use new Domain Controller for DNS resolution
psexec64.exe \\172.17.0.26 -u demo -p Crowdstrike2017! -i -h netsh interface ipv4 set dns name="Ethernet" static 172.17.0.34
psexec64.exe \\172.17.0.30 -u demo -p Crowdstrike2017! -i -h netsh interface ipv4 set dns name="Ethernet" static 172.17.0.34
psexec64.exe \\172.17.0.29 -u badguy -p Crowdstrike2017! -i -h netsh interface ipv4 set dns name="Ethernet" static 172.17.0.34
 
#STEP12 
$AD_Additional = {
#Collect Variable Hosts from SE Lab machine. Collects characters at position 10-12.
$SE_Initials_W2019 = $env:computername.split("-")[1]
$counter=$SE_Initials_W2019.Substring($SE_Initials_W2019.get_Length()-1)
$SE_Initials_W2019=$SE_Initials_W2019.Substring(0,$SE_Initials_W2019.Length-1)
$Mydate=Get-Date -Format "MMdd"
$DomainName = $SE_Initials_W2019 + $Mydate + ".com"
$DomainShort=$SE_Initials_W2019 + $Mydate
$NameShort=$SE_Initials_W2019+$counter
$computerBL="SE-"+ $SE_Initials_W2019 +""+ $counter +"-W10-BL"
$computerDT="SE-"+ $SE_Initials_W2019 +""+ $counter +"-W10-DT"
$computerCO="SE-"+ $SE_Initials_W2019 +""+ $counter +"-W10-CO"
$computerDC="SE-"+ $SE_Initials_W2019 +""+ $counter +"-W19-DT"
#Update DNS Records for Lab machines
Add-DnsServerResourceRecordA -Name "$computerDT" -IPv4Address 172.17.0.26 -ZoneName $DomainName
Add-DnsServerResourceRecordA -Name "$computerBL" -IPv4Address 172.17.0.30 -ZoneName $DomainName
Add-DnsServerResourceRecordA -Name "$computerCO" -IPv4Address 172.17.0.29 -ZoneName $DomainName
 
#YOU SHOULD ALSO CHANGE THOSE NAMES IF NEEDED
#AD User Creation
New-ADUser -Name “Simon Quentel_$NameShort” -SamAccountName “squentel_$NameShort” -GivenName “Simon” -Surname “squentel_$NameShort” -Path “CN=Users,DC=$DomainShort,DC=com” -AccountPassword(ConvertTo-SecureString "Crowdstrike2017!" -AsPlainText -force) -Enabled $true
New-ADUser -Name “Fabrice Martin_$NameShort” -SamAccountName “fmartin_$NameShort” -GivenName “Fabrice” -Surname “fmartin_$NameShort” -Path “CN=Users,DC=$DomainShort,DC=com” -AccountPassword(ConvertTo-SecureString "Crowdstrike2017!" -AsPlainText -force) -Enabled $true
# Add SPN User for kerberoasting
Set-ADUser -Identity "fmartin_$NameShort" -ServicePrincipalNames @{Add='HTTP/webserver'}
   
#Creds
$creduser = "demo"
$credpass = convertto-securestring -String "Crowdstrike2017!" -AsPlainText -Force
$local_cred1 = new-object -typename System.Management.Automation.PSCredential -argumentlist $creduser,$credpass
$creduser = "badguy"
$credpass = convertto-securestring -String "Crowdstrike2017!" -AsPlainText -Force
$local_cred2 = new-object -typename System.Management.Automation.PSCredential -argumentlist $creduser,$credpass
$Aduser = "$DomainShort\administrator"
$Adpass = convertto-securestring -string "Crowdstrike2017!" -AsPlainText -Force
$Adcred2 = new-object -typename System.Management.Automation.PSCredential -argumentlist $Aduser,$Adpass
   
#Add Lab Machine's BL and DT to AD Domain
Add-computer -domainname "$DomainName" -credential $Adcred2 -computername "$computerDT.$DomainName", "$computerBL.$DomainName" -localcredential $local_cred1 -restart
   
#Add Lab Machine CO to AD Domain
Add-computer -domainname "$DomainName" -credential $Adcred2 -computername "$computerCO.$DomainName" -localcredential $local_cred2 -restart
}
 
#STEP13
$SE_Initials_W2019 = $env:computername.split("-")[1]
$DomainName = $SE_Initials_W2019 + $Mydate + ".com"
$DomainShort=$SE_Initials_W2019 + $Mydate
$Aduser="$DomainShort\administrator"
$Adpass = convertto-securestring -string "Crowdstrike2017!" -AsPlainText -Force
$Adcred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Aduser,$Adpass
Connect-PSSession -ComputerName "$computerDC.$DomainName" –credential $Adcred
Invoke-Command -Computer "$computerDC" -Script $AD_Additional –credential $Adcred
   
#STEP14
#Pause script for 4 minutes to wait for Lab Machine reboot's to complete
$x = 4*60
$length = $x / 100
while($x -gt 0) {
$min = [int](([string]($x/60)).split('.')[0])
$text = " " + $min + " minutes " + ($x % 60) + " seconds left"
Write-Progress "Pausing Script while waiting for reboot to complete" -status $text -perc ($x/$length)
start-sleep -s 1
$x--
}
   
#STEP15 -  NOTE THAT IF YOU CHANGED THE USERS NAME YOU SHOULD REPORT THOSE CHANGE IN THE LAST LINES HERE TOO
#Setup AD Users as local admins on endpoints
$Local_Admin= {
#Collect Variable Hosts from SE Lab machine.
$Mydate=Get-Date -Format "MMdd"
$SE_Initials_W2019 = $env:computername.split("-")[1]
$counter=$SE_Initials_W2019.Substring($SE_Initials_W2019.get_Length()-1)
$SE_Initials_W2019=$SE_Initials_W2019.Substring(0,$SE_Initials_W2019.Length-1)
$DomainName = $SE_Initials_W2019 + $Mydate + ".com"
$DomainShort=$SE_Initials_W2019 +$Mydate
$NameShort=$SE_Initials_W2019+$counter
$computerBL="SE-"+ $SE_Initials_W2019 +""+ $counter +"-W10-BL"
$computerDT="SE-"+ $SE_Initials_W2019 +""+ $counter +"-W10-DT"
$computerCO="SE-"+ $SE_Initials_W2019 +""+ $counter +"-W10-CO"
psexec64 \\$computerCO.$DomainName -accepteula -u $DomainShort\administrator -p Crowdstrike2017! -i -h net localgroup "Administrators" "$DomainShort\fmartin_$NameShort" /add
psexec64 \\$computerDT.$DomainName -u $DomainShort\administrator -p Crowdstrike2017! -accepteula -i -h net localgroup "Administrators" "$DomainShort\squentel_$NameShort" /add
psexec64 \\$computerBL.$DomainName -u $DomainShort\administrator -p Crowdstrike2017! -accepteula -i -h net localgroup "Administrators" "$DomainShort\squentel_$NameShort" /add
}
 
 
#STEP16
Invoke-Command -Computer $computerDC -Script $Local_Admin –credential $Adcred
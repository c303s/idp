#Discover current domain name
$DomainName = (Get-ADDomain).DNSRoot
$DistinguishedName = (Get-ADDomain).DistinguishedName
$count = "C" # <----- please manipulate this line


#Check to see if the OU already exists in AD
if (Get-ADOrganizationalUnit -LDAPFilter "(name=TestUsers)" -SearchScope Subtree -SearchBase $DistinguishedName)
    {
    Write-Warning "An OU with this name already exists."
    }
    else
    {
    New-ADOrganizationalUnit  -DisplayName "Test Users" -Name "TestUsers" -ProtectedFromAccidentalDeletion $False -Path $DistinguishedName
    }

#Add users
@(1..30).foreach{
    $Username ="tuser_" + $counter + "_" + "$_"
    $Password = "Crowdstrike2017!"
    $Firstname = "Test" + "$counter"
    $Lastname = "User$_"
    $OU = "OU=TestUsers,$DistinguishedName"

#Check to see if the user already exists in AD
if (Get-ADUser -F {SamAccountName -eq $Username})
            {
            #If user does exist, give a warning
            Write-Warning "A user account with username $Username already exist."
            }

            else
            {                       
            #Account will be created in the OU provided by the $OU variable read from the CSV file
            New-ADUser `
            -SamAccountName $Username `
            -UserPrincipalName "$Username@acme.local" `
            -Name "$Firstname $Lastname" `
            -GivenName $Firstname `
            -Surname $Lastname `
            -Enabled $True `
            -DisplayName "$Lastname, $Firstname" `
            -Path $OU `
            -AccountPassword (convertto-securestring $Password -AsPlainText -Force) -ChangePasswordAtLogon $True
            }
} 
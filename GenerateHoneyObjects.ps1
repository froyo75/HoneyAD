<#
.SYNOPSIS
    Create/Update HoneyUsers, HoneyServices, HoneyComputers and SPNS to lure attackers.
.DESCRIPTION
    Imports CSV files which contain the HoneyUser, Service, SPN, Group, OU, Computer objects and ACLS.
    Specific AD attributes can be set within the CSV file:
        - To add or replace a custom object attribute (for example: the LDAP attribute "userPassword" -> this attribute stores an ASCII-decimal encoded format of the password) 
        - To add or update a specific description revealing a temporary password.
        - To set an account password to never expire within the "PasswordNeverExpires" attribute
        - To enforce (or not) Kerberos pre-authentication which could allow AS-REP roasting attacks
        - To add or replace one or more SPN for a specific domain user account
        - To add a domain user to one or more Active Directory groups within the "memberOf" attribute (default list separator '|' -> can be changed through the "$memberOfSeparator" variable)
        - Specific ACLs can also be set to change the security descriptor of a specified AD user, group or computer object.
.NOTES
    Version:        2.3
    Author:         @froyo75
    Creation Date:  10/09/2020
    Purpose/Change: 
        - 1.0 Initial script development
        - 1.1 Several fixes
        - 1.2 Add Computer objects support
        - 1.3 Add ACLS support + some major fixes and improvements
        - 1.4 Logging improvements
        - 1.5 Add Clear feature for flushing all objects + several improvements
        - 1.6 Add Group object support for setting ACLS
        - 1.7 Add None default value for "CustomAttribute", "MemberOf" and "SPN" fields
        - 1.8 Add CSV delimiter option
        - 1.9 Fix 'ManagedBy' attribute support for computer objects
        - 2.0 Fix 'doesNotRequirePreAuth' attribute support for user objects
        - 2.1 Fix 'OU' creation/deletion issues
        - 2.2 Add/Fix 'Domain/Server' support
        - 2.3 Fix issues when displaying SPNs in log Messages
.EXAMPLE
    #To create all Active Directory objects specified within the CSV
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileOUGroups  C:\Users\Administrator\Desktop\RS\OUGroups.csv
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileUsersServices C:\Users\Administrator\Desktop\RS\UsersServices.csv
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileComputers C:\Users\Administrator\Desktop\RS\Computers.csv
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileACLS C:\Users\Administrator\Desktop\RS\ACLS.csv

    #To force updating all Active Directory objects specified within the CSV
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileOUGroups  C:\Users\Administrator\Desktop\RS\OUGroups.csv -Update $true
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileUsersServices C:\Users\Administrator\Desktop\RS\UsersServices.csv -Update $true
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileComputers C:\Users\Administrator\Desktop\RS\Computers.csv -Update $true
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileACLS C:\Users\Administrator\Desktop\RS\ACLS.csv -Update $true
    
    #To remove all Active Directory objects specified within the CSV
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileOUGroups  C:\Users\Administrator\Desktop\RS\OUGroups.csv -Clear $true
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileUsersServices C:\Users\Administrator\Desktop\RS\UsersServices.csv -Clear $true
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileComputers C:\Users\Administrator\Desktop\RS\Computers.csv -Clear $true
    C:\PS> GenerateHoneyObjects -CSVDelimiter ';' -CSVFileACLS C:\Users\Administrator\Desktop\RS\ACLS.csv -Clear $true
#>

$memberOfSeparator = '|'

function Get-DateTime() {
    return $(Get-Date -UFormat "%m/%d/%Y %T")
}

function Logging([string]$Message, [string]$Color, [string]$LogFile, [bool]$WriteToLog, [bool]$DisplayMessage) {
    Try {
        if ($Message -ne "" -and $Message -ne $null) {
            if ($WriteToLog) {
                Add-content $LogFile -value $Message
            }

            if ($DisplayMessage) {
                Write-Host $Message -foregroundcolor $Color
            }
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

function Check-ADUserOrComputerSPN([object]$ADObject, [string]$Domain) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $SPNS = $ADObject.ServicePrincipalNames
        $SPNList = ($SPNS | % { "'$_'" } | out-string).Replace("`n",",").TrimEnd(',')
        $Exist = [bool]$SPNS
        if ($Exist) {
            $Message = "[*] $(Get-DateTime): The following SPN(s) {$SPNList} are set for the domain object '$Domain\$SamAccountName'"
            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        return $Exist
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Check-ADUserOrComputerInGroup([string]$SamAccountName, [string]$Server, [string]$Domain, [string]$Group) {
    Try {
        $Exist = [bool](Get-ADGroupMember -Server $Server -Identity $Group | ? {$_.SamAccountName -eq $SamAccountName})
        if (-Not $Exist) {
            $Message = "[*] $(Get-DateTime): The domain object '$Domain\$SamAccountName' does not belong to the '$Group' group !"
            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        return $Exist
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Get-ADOUOrGroup([string]$Domain, [string]$Server, [string]$Attribute, [string]$ObjectType) {
    Try {
        if ($ObjectType -like "ou") {
            $ADObject = (Get-ADOrganizationalUnit -Server $Server -Filter { DistinguishedName -eq $Attribute } -Properties *)
            $ObjectName = "organizational unit (OU)"
        } elseif ($ObjectType -like "group") {
            $ADObject = (Get-ADGroup -Server $Server -Filter { SamAccountName -eq $Attribute } -Properties *)
            $ObjectName = "Active Directory group"
        }
        $Exist = [bool]$ADObject
        if (-Not $Exist) {
            $Message = "[!] $(Get-DateTime): The $ObjectName '$Attribute' does not exist within the domain '$Domain' !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            return $false
        } else {
            return $ADObject
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Set-KerberosPreAuth([object]$ADObject, [string]$Server, [string]$Domain, [bool]$RequirePreAuth, [bool]$Update) {
    Try {
        if($ADObject) {
            $SamAccountName = $ADObject.SamAccountName
            $DoesNotRequirePreAuth = [bool]$ADObject.DoesNotRequirePreAuth
            if(($DoesNotRequirePreAuth -ne $RequirePreAuth) -or $Update) {
                $Message = "[+] $(Get-DateTime): Setting Kerberos pre-authentication for the domain object '$Domain\$SamAccountName' to '$RequirePreAuth'"
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                Set-ADAccountControl -Server $Server -DoesNotRequirePreAuth $RequirePreAuth -Identity $SamAccountName
            }    
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Get-ADUserOrComputerObject([string]$Server, [string]$Domain, [string]$SamAccountName, [string]$ObjectType) {
    Try {
        if ($ObjectType -like "user") {
            $ADObject = (Get-ADUser -Server $Server -Filter { SamAccountName -eq $SamAccountName } -Properties *)
        } elseif ($ObjectType -like "computer") {
            $ADObject = (Get-ADComputer -Server $Server -Filter { SamAccountName -eq $SamAccountName } -Properties *)
        }
        $Exist = [bool]$ADObject
        if (-Not $Exist) {
            $Message = "[!] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' does not exist !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            return $false
        } else {
            return $ADObject
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Check-CustomAttribute([object]$ADObject, [bool]$Update, [string]$Domain, [string]$SamAccountName, [string]$CustomAttribute) {
    Try {
        if (($CustomAttribute -ne "" ) -and ($CustomAttribute -ne "None")) {
            $CustomAttributeKey = ($CustomAttribute.split('='))[0]
            $CustomAttributeObject = (ConvertFrom-StringData -StringData $CustomAttribute)
            if ($ADObject) {
                $ExistCustomAttribute = [bool]$ADObject.$CustomAttributeKey
                if ($ExistCustomAttribute -and $Update) {
                    $Message = "[*] $(Get-DateTime): The custom attribute '$CustomAttribute' already exists for the domain object '$Domain\$SamAccountName' ! (Replacing..)"
                    Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                } elseif (-Not $ExistCustomAttribute) {
                    $Message = "[+] $(Get-DateTime): The custom attribute '$CustomAttribute' does not exist for the domain object '$Domain\$SamAccountName'. (Adding...)"
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                } 
            }
            return $CustomAttributeObject, $ExistCustomAttribute
        }
        return $false
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Set-ADManagedByComputer([object]$ADComputerObject, [string]$Server, [string]$Domain, [string]$ManagedBy) {
    Try {
        if($ADComputerObject) {
            $SamAccountName = $ADComputerObject.SamAccountName
            $ExistManagedBy = [bool]$ADComputerObject.ManagedBy
            if (($ManagedBy -ne "" ) -and ($ManagedBy -ne "None")) {
                $Message = "[+] $(Get-DateTime): Setting 'ManagedBy' attribute to '$ManagedBy' for the computer object '$Domain\$SamAccountName'"
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                Set-ADComputer -Server $Server -Identity $SamAccountName -ManagedBy $ManagedBy
            } elseif ($ExistManagedBy) {
                $Message = "[-] $(Get-DateTime): Clearing 'ManagedBy' attribute for the computer object '$Domain\$SamAccountName' !"
                Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                Set-ADComputer -Server $Server -Identity $SamAccountName -Clear ManagedBy
            }
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Set-ADComputerObject([object]$ADComputerObject, [string]$Server, [string]$Domain, [string]$SamAccountName, [SecureString]$Password, [string]$Name, [string]$DisplayName, [string]$UserPrincipalName, [string]$Description, [string]$DNSHostName, [string]$HomePage, [string]$Location, `
[string]$OperatingSystem, [string]$OperatingSystemHotfix, [string]$OperatingSystemServicePack, [string]$OperatingSystemVersion, [string]$OU, [bool]$PasswordNeverExpires, [bool]$TrustedForDelegation, [string]$CustomAttribute, [bool]$Enabled, `
[string]$KerberosEncryptionType, [bool]$Update) {
    Try {
        $CustomAttributeObject, $ExistAttribute = (Check-CustomAttribute -ADObject $ADComputerObject -Update $Update -Domain $Domain -Server $Server -SamAccountName $SamAccountName -CustomAttribute $CustomAttribute)
        if (-Not $ADComputerObject) {
            $Message = "[+] $(Get-DateTime): Creating the domain computer '$Domain\$SamAccountName'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            if ($CustomAttributeObject) {
                New-ADComputer -Server $Server -Name $Name -DisplayName $DisplayName -Description $Description -DNSHostName $DNSHostName `
                -HomePage $HomePage -Location $Location -OperatingSystem $OperatingSystem -OperatingSystemHotfix $OperatingSystemHotfix -OperatingSystemServicePack $OperatingSystemServicePack `
                -OperatingSystemVersion $OperatingSystemVersion -SamAccountName $SamAccountName -AccountPassword $Password -Path $OU -PasswordNeverExpires $PasswordNeverExpires `
                -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -KerberosEncryptionType $KerberosEncryptionType -UserPrincipalName $UserPrincipalName `
                -OtherAttributes $CustomAttributeObject -ChangePasswordAtLogon $false
            } else {
                New-ADComputer -Server $Server -Name $Name -DisplayName $DisplayName -Description $Description -DNSHostName $DNSHostName `
                -HomePage $HomePage -Location $Location -OperatingSystem $OperatingSystem -OperatingSystemHotfix $OperatingSystemHotfix -OperatingSystemServicePack $OperatingSystemServicePack `
                -OperatingSystemVersion $OperatingSystemVersion -SamAccountName $SamAccountName -AccountPassword $Password -Path $OU -PasswordNeverExpires $PasswordNeverExpires `
                -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -KerberosEncryptionType $KerberosEncryptionType -UserPrincipalName $UserPrincipalName `
                -ChangePasswordAtLogon $false
            }
        } elseif ($ADComputerObject -and $Update) {
            $Message = "[+] $(Get-DateTime): Updating the domain computer '$Domain\$SamAccountName'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            if ($CustomAttributeObject -and $ExistAttribute) {
                Set-ADComputer -Server $Server -Identity $SamAccountName -DisplayName $DisplayName -Description $Description -DNSHostName $DNSHostName `
                -HomePage $HomePage -Location $Location -OperatingSystem $OperatingSystem -OperatingSystemHotfix $OperatingSystemHotfix -OperatingSystemServicePack $OperatingSystemServicePack `
                -OperatingSystemVersion $OperatingSystemVersion -SamAccountName $SamAccountName -PasswordNeverExpires $PasswordNeverExpires `
                -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -KerberosEncryptionType $KerberosEncryptionType -UserPrincipalName $UserPrincipalName `
                -ChangePasswordAtLogon $false -Replace $CustomAttributeObject 
            } elseif ($CustomAttributeObject -and -not $ExistAttribute) {
                Set-ADComputer -Server $Server -Identity $SamAccountName -DisplayName $DisplayName -Description $Description -DNSHostName $DNSHostName `
                -HomePage $HomePage -Location $Location -OperatingSystem $OperatingSystem -OperatingSystemHotfix $OperatingSystemHotfix -OperatingSystemServicePack $OperatingSystemServicePack `
                -OperatingSystemVersion $OperatingSystemVersion -SamAccountName $SamAccountName -PasswordNeverExpires $PasswordNeverExpires `
                -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -KerberosEncryptionType $KerberosEncryptionType -UserPrincipalName $UserPrincipalName `
                -ChangePasswordAtLogon $false -Add $CustomAttributeObject 
            } else {
                Set-ADComputer -Server $Server -Identity $SamAccountName -DisplayName $DisplayName -Description $Description -DNSHostName $DNSHostName `
                -HomePage $HomePage -Location $Location -OperatingSystem $OperatingSystem -OperatingSystemHotfix $OperatingSystemHotfix -OperatingSystemServicePack $OperatingSystemServicePack `
                -OperatingSystemVersion $OperatingSystemVersion -SamAccountName $SamAccountName -PasswordNeverExpires $PasswordNeverExpires `
                -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -KerberosEncryptionType $KerberosEncryptionType -UserPrincipalName $UserPrincipalName `
                -ChangePasswordAtLogon $false
            }
        } else {
            $Message = "[*] $(Get-DateTime): The domain computer '$Domain\$SamAccountName' already exists !"
            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Set-ADUserObject([object]$ADUserObject, [string]$Server, [string]$Domain, [string]$SamAccountName, [SecureString]$Password, [string]$Name, [string]$DisplayName, [string]$GivenName, [string]$UserPrincipalName, `
 [string]$Description, [string]$OU, [bool]$PasswordNeverExpires, [bool]$TrustedForDelegation, [string]$CustomAttribute, [bool]$Enabled, [bool]$Update) {
    Try {
        $CustomAttributeObject, $ExistAttribute = (Check-CustomAttribute -ADObject $ADUserObject -Update $Update -Domain $Domain -Server $Server -SamAccountName $SamAccountName -CustomAttribute $CustomAttribute)
        if (-Not $ADUserObject) {
            $Message = "[+] $(Get-DateTime): Creating the domain user '$Domain\$SamAccountName'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            if ($CustomAttributeObject) {
                New-ADUser -Server $Server -SamAccountName $SamAccountName -AccountPassword $Password -Name $Name -DisplayName $DisplayName -GivenName $GivenName -UserPrincipalName $UserPrincipalName `
                 -Description $Description -Path $OU -PasswordNeverExpires $PasswordNeverExpires -TrustedForDelegation $TrustedForDelegation -OtherAttributes $CustomAttributeObject -Enabled $Enabled `
                 -ChangePasswordAtLogon $false
            } else {
                New-ADUser -Server $Server -SamAccountName $SamAccountName -AccountPassword $Password -Name $Name -DisplayName $DisplayName -GivenName $GivenName -UserPrincipalName $UserPrincipalName `
                 -Description $Description -Path $OU -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -ChangePasswordAtLogon $false
            }
        } elseif ($ADUserObject -and $Update) {
            $Message = "[+] $(Get-DateTime): Updating the domain user '$Domain\$SamAccountName'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            if ($CustomAttributeObject -and $ExistAttribute) {
                Set-ADUser -Server $Server -Identity $SamAccountName -SamAccountName $SamAccountName -DisplayName $DisplayName -GivenName $GivenName -UserPrincipalName $UserPrincipalName `
                 -Description $Description -PasswordNeverExpires $PasswordNeverExpires -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -ChangePasswordAtLogon $false -Replace $CustomAttributeObject
            } elseif ($CustomAttributeObject -and -not $ExistAttribute) {
                Set-ADUser -Server $Server -Identity $SamAccountName -SamAccountName $SamAccountName -DisplayName $DisplayName -GivenName $GivenName -UserPrincipalName $UserPrincipalName `
                 -Description $Description -PasswordNeverExpires $PasswordNeverExpires -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -ChangePasswordAtLogon $false -Add $CustomAttributeObject
            } else {
                Set-ADUser -Server $Server -Identity $SamAccountName -SamAccountName $SamAccountName -DisplayName $DisplayName -GivenName $GivenName -UserPrincipalName $UserPrincipalName `
                 -Description $Description -PasswordNeverExpires $PasswordNeverExpires -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -ChangePasswordAtLogon $false
            }
        } else {
            $Message = "[*] $(Get-DateTime): The domain user '$Domain\$SamAccountName' already exists !"
            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Remove-ADUserOrComputerFromGroups([object]$ADObject, [string]$Server, [string]$Domain) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $PrimaryGroup = $ADObject.PrimaryGroup
        $GroupsArray = (Get-ADPrincipalGroupMembership -identity $SamAccountName -Server $Server).distinguishedName
        foreach ($Group in $GroupsArray) {
            # The primary group of the domain user cannot be removed.
            if ($Group -NotLike $PrimaryGroup) {
                $Message = "[-] $(Get-DateTime): Removing the domain object '$Domain\$SamAccountName' from the '$Group' group"
                Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                Remove-ADGroupMember -Confirm:$False -Server $Server -Identity $Group -Members $SamAccountName
            }
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Set-ADUserOrComputerGroups([object]$ADObject, [string]$Server, [string]$Domain, [string]$MemberOf, [bool]$Update) {
    Try {
        if($ADObject) {
            if (($MemberOf -ne "") -and ($MemberOf -ne "None")) {
                $SamAccountName = $ADObject.SamAccountName
                if ($Update) { Remove-ADUserOrComputerFromGroups -ADObject $ADObject -Domain $Domain -Server $Server }
                $MemberOfArray = $MemberOf.split($memberOfSeparator)
                foreach ($Group in $MemberOfArray) {
                    if ($Group -ne "") {
                        $ExistInGroup = Check-ADUserOrComputerInGroup -SamAccountName $SamAccountName -Domain $Domain -Server $Server -Group $Group
                        if (-Not $ExistInGroup) {
                            $Message = "[+] $(Get-DateTime): Adding the domain object '$Domain\$SamAccountName' to the '$Group' group"
                            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                            Add-ADPrincipalGroupMembership -Server $Server -Identity $SamAccountName -MemberOf $Group
                        } else {
                            $Message = "[*] $(Get-DateTime): The domain object '$Domain\$SamAccountName' belongs to the '$Group' group"
                            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                        }
                    }
                }
            } else {
                Remove-ADUserOrComputerFromGroups -ADObject $ADObject -Domain $Domain -Server $Server
            }
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Set-ADSPNUserOrComputer([object]$ADObject, [string]$Server, [string]$Domain, [string]$SPN, [bool]$Update, [string]$ObjectType) {
    Try {
        if ($ADObject) {
            $SamAccountName = $ADObject.SamAccountName
            if (($SPN -ne "") -and ($SPN -ne "None")) {
                if ($ObjectType -like "user") {
                    $CMD = "Set-ADUser -Server $Server -Identity $SamAccountName"
                } elseif ($ObjectType -like "computer") {
                    $CMD = "Set-ADComputer -Server $Server -Identity $SamAccountName"
                }
                $ExistSPN = Check-ADUserOrComputerSPN -ADObject $ADObject -Domain $Domain
                if (-Not $ExistSPN) {
                    $Message = "[+] $(Get-DateTime): Creating the following SPN(s) {$SPN} for the domain $ObjectType '$Domain\$SamAccountName'"
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    iex("$CMD -ServicePrincipalNames @{Add=$SPN}")
                } elseif ($ExistSPN -and $Update) {
                    $Message = "[+] $(Get-DateTime): Updating the following SPN(s) {$SPN} for the domain $ObjectType '$Domain\$SamAccountName'"
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    iex("$CMD -ServicePrincipalNames @{Replace=$SPN}")
                }
            } else {
                $Message = "[-] $(Get-DateTime): Clearing all SPN(s) for the domain $ObjectType '$Domain\$SamAccountName' !"
                Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                Set-ADUser -Server $Server -Identity $SamAccountName -ServicePrincipalNames $null
            }
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Set-ADGroups([object]$ADGroupObject, [string]$Server, [string]$Domain, [string]$SamAccountName, [string]$Name, [string]$DisplayName, [string]$Description, [string]$OU, [bool]$Update) {
    Try {
        if (-Not $ADGroupObject) {
            $Message = "[+] $(Get-DateTime): Creating the Active Directory group '$Name' within the domain '$Domain'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            New-ADGroup -GroupScope Global -SamAccountName $SamAccountName -Name $Name -DisplayName $DisplayName -Description $Description -Path $OU -Server $Server
        } elseif ($ADGroupObject -and $Update) {
            $Message = "[+] $(Get-DateTime): Updating the Active Directory group '$Name' within the domain '$Domain'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            Set-ADGroup -Identity $Name -SamAccountName $SamAccountName -DisplayName $DisplayName -Description $Description -Server $Server
        } else {
            $Message = "[*] $(Get-DateTime): The Active Directory group '$Name' already exists within the domain '$Domain' !"
            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Set-ADOU([object]$ADOUObject, [string]$Server, [string]$Domain, [string]$Name, [string]$DisplayName, [string]$Description, [string]$OU, [bool]$Update) {
    Try {
        if (-Not $ADOUObject) {
            $Message = "[+] $(Get-DateTime): Creating the organizational unit '$Name' within the domain '$Domain'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            New-ADOrganizationalUnit -Name $Name -DisplayName $DisplayName -Description $Description -Path $OU -Server $Server
        } elseif ($ADOUObject -and $Update) {
            $Message = "[+] $(Get-DateTime): Updating the organizational unit '$Name' within the domain '$Domain'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            $Identity = "OU=$Name,$OU"
            Set-ADOrganizationalUnit -Identity $Identity -DisplayName $DisplayName -Description $Description -Server $Server
        } else {
            $Message = "[*] $(Get-DateTime): The organizational unit '$Name' already exists within the domain '$Domain' !"
            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Set-ACLSObject([string]$Server, [string]$Domain, [string]$SourceSamAccountName, [string]$SourceObjectType, [string]$TargetSamAccountName, [string]$TargetObjectType, `
[string]$ADRight, [string]$AccessType, [string]$SecurityInheritance, [bool]$Update, [bool]$Clear) {
    Try {
        $CommitACL = $false

        if ($SourceObjectType -eq "group") {
            $SourceADObject = Get-ADOUOrGroup -Domain $Domain -Server $Server -Attribute $SourceSamAccountName -ObjectType group
        } else {
            $SourceADObject = Get-ADUserOrComputerObject -Domain $Domain -Server $Server -SamAccountName $SourceSamAccountName -ObjectType $SourceObjectType
        }

        if ($TargetObjectType -eq "group") {
            $TargetADObject = Get-ADOUOrGroup -Domain $Domain -Server $Server -Attribute $TargetSamAccountName -ObjectType group
        } else {
            $TargetADObject = Get-ADUserOrComputerObject -Domain $Domain -Server $Server -SamAccountName $TargetSamAccountName -ObjectType $TargetObjectType
        }
        
        $NewLocation = $Domain.Replace('.','-')
        $Message = "[+] $(Get-DateTime): Creating a temporary drive '$NewLocation' that are mapped to the '$Domain' domain"
        Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        New-PSDrive -Name $NewLocation -PSProvider ActiveDirectory -Server $Server -Scope Global -root "//RootDSE/" | Out-Null
        Set-Location $NewLocation`:

        if ($SourceADObject -and $TargetADObject) {
            $TargetIdentityReference = (($Domain.split('.')[0]).ToUpper()) + '\' + $TargetSamAccountName
            $SourceDistinguishedName = $SourceADObject.DistinguishedName
            $CurrentObjectACLS = (Get-Acl $SourceDistinguishedName)
            $CurrentACLSIdentityReference = ($CurrentObjectACLS).access | ? {$_.IdentityReference -like $TargetIdentityReference}
            $ExistIdentityReference = [bool]$CurrentACLSIdentityReference

            if ($Clear) {
                $Message = "[-] $(Get-DateTime): Removing all ACLS for the identity reference '$TargetIdentityReference' on '$SourceDistinguishedName' object. (Clearing...) !"
                Logging -Message $Message -Color "magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                $Success = $CurrentObjectACLS.RemoveAccessRule($CurrentACLSIdentityReference)
                if ($Success) {
                    $Message = "[+] $(Get-DateTime): All ACLS for the identity reference '$TargetIdentityReference' have been successfully removed on '$SourceDistinguishedName' object !"
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    $CommitACL = $true
                } else {
                    $Message = "[!] $(Get-DateTime): Error deleting ACLS for the identity reference '$TargetIdentityReference' on '$SourceDistinguishedName' object !"
                    Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                }
            } elseif ($ADRight -ne "" -and $AccessType -ne "" -and $SecurityInheritance -ne "") {
                $TargetObjectSID = $TargetADObject.SID
                $IdentityObject = [System.Security.Principal.IdentityReference] $TargetObjectSID
                $ADRightObject = [System.DirectoryServices.ActiveDirectoryRights] $ADRight
                $AccessTypeObject = [System.Security.AccessControl.AccessControlType] $AccessType
                $InheritanceTypeObject = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $SecurityInheritance
                $NewACL = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityObject,$ADRightObject,$AccessTypeObject,$InheritanceTypeObject

                if (-Not $ExistIdentityReference) {
                    $Message = "[+] $(Get-DateTime): The identity reference '$TargetIdentityReference' does not exist on '$SourceDistinguishedName' object. (Adding...)"
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    $CurrentObjectACLS.AddAccessRule($NewACL)
                    $CommitACL = $true
                } else {
                    $Message = "[*] $(Get-DateTime): The identity reference '$TargetIdentityReference' already exists on '$SourceDistinguishedName' object !"
                    Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    if ($Update) {
                        $Success = $CurrentObjectACLS.RemoveAccessRule($CurrentACLSIdentityReference)
                        if ($Success) {
                            $Message = "[+] $(Get-DateTime): ACLS for the identity reference '$TargetIdentityReference' successfully removed on '$SourceDistinguishedName' object ! (Replacing with new ACL rules...)"
                            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                            $CurrentObjectACLS.AddAccessRule($NewACL)
                            $CommitACL = $true
                        } else {
                            $Message = "[!] $(Get-DateTime): Error deleting ACLS for the identity reference '$TargetIdentityReference' on '$SourceDistinguishedName' object !"
                            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                        }
                    }
                } 
            } 
            
            if($CommitACL) {
                $Message = "[+] $(Get-DateTime): Applying changes to '$SourceDistinguishedName'..."
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                set-acl -aclobject $CurrentObjectACLS $SourceDistinguishedName
                #(Get-Acl $SourceDistinguishedName).Access | select IdentityReference,ActiveDirectoryRights,AccessControlType,InheritanceType
            }
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } Finally {
        Set-Location $PSScriptRoot
        $Message = "[-] $(Get-DateTime): Removing the temporary drive '$NewLocation' that are mapped to the '$Domain' domain"
        Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        Remove-PSDrive -Name $NewLocation
    }
}

function Delete-ADObject([string]$Server, [string]$Domain, [string]$DistinguishedName, [string]$ObjectType) {
    Try {  
        $Message = "[-] $(Get-DateTime): Removing protection to prevent the domain $ObjectType object '$DistinguishedName' from being deleted !"
        Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        Set-ADObject -Identity $DistinguishedName -Server $Server -ProtectedFromAccidentalDeletion:$false -Confirm:$false
        $Message = "[-] $(Get-DateTime): Removing the domain $ObjectType object '$DistinguishedName' within the domain '$Domain' !"
        Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        Remove-ADObject -Identity $DistinguishedName -Server $Server -Recursive -Confirm:$false
    } Catch {
            $Message = "[!] $(Get-DateTime): $_.Exception.Message"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function GenerateHoneyObjects
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the input CSV file for creating/or updating users, services objects and set SPNs.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFileUsersServices,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the input CSV file for creating/or updating OU and Group objects.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFileOUGroups,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the input CSV file for creating/or updating computer objects.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFileComputers,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the input CSV file for setting/or updating the security descriptor of a specified object.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFileACLS,

        [Parameter(Mandatory=$false,
                HelpMessage="Specify the domain controller to use (Default => The default primary domain controller).")]
        [ValidateNotNullOrEmpty()]
        [string]$Server = (Get-ADDomain).pdcEmulator,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the CSV delimiter (Default=',').")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVDelimiter = ',',

        [Parameter(Mandatory=$false,
                   HelpMessage="Whether to force writing output messages to log file (Default=False).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($false,$true)]
        [bool]$Update = $false,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the log path for logging messages (Default=<Current Working Directory>).")]
        [ValidateNotNullOrEmpty()]
        [string]$LogFile = "$PSScriptRoot\$($MyInvocation.Mycommand.Name).log",

        [Parameter(Mandatory=$false,
                   HelpMessage="Whether to force writing output messages (Default=True).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($false,$true)]
        [bool]$WriteToLog = $true,

        [Parameter(Mandatory=$false,
                   HelpMessage="Whether to force displaying output messages (Default=True).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($false,$true)]
        [bool]$DisplayMessage = $true,

        [Parameter(Mandatory=$false,
                   HelpMessage="To remove all Active Directory objects specified within the CSV (Default=False).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($false,$true)]
        [bool]$Clear = $false
    )

    Begin {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
           $Message = "[+] $(Get-DateTime): Active Directory module exists"
           Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $false -DisplayMessage $DisplayMessage
        } else {
           $Message = "[!] $(Get-DateTime): Active Directory module does not exist !"
           Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $true -DisplayMessage $DisplayMessage
           exit
        }
    }

    process {
        Try {
            if ($PSBoundParameters.ContainsKey("CSVFileOUGroups")) {
                $CSVOUGroups = Import-Csv -Path $CSVFileOUGroups -Delimiter $CSVDelimiter
                #####Creating/Updating Organizational Units + Groups#####
                foreach ($dataOUGroups in $CSVOUGroups) {
                    $ObjectType = $dataOUGroups.objectType
                    $Domain = $dataOUGroups.domain
                    $Name = $dataOUGroups.name
                    $DisplayName = $dataOUGroups.displayName
                    $Description = $dataOUGroups.description
                    $SamAccountName = $dataOUGroups.samAccountName
                    $OU = $dataOUGroups.ou
                    if ($ObjectType -like "ou") {
                        $DistinguishedName = "OU=$Name,$OU"
                        $ADOUObject = Get-ADOUOrGroup -Domain $Domain -Server $Server -Attribute $DistinguishedName -ObjectType "ou"
                        if($Clear) {
                            if ($ADOUObject) {
                                Delete-ADObject -Domain $Domain -Server $Server -DistinguishedName $DistinguishedName -ObjectType "ou"
                            }
                        } else {
                            Set-ADOU -ADOUObject $ADOUObject -Domain $Domain -Server $Server -Name $Name -DisplayName $DisplayName -Description $Description -OU $OU -Update $Update
                        }
                    } elseif ($ObjectType -like "group") {
                        $ADGroupObject = Get-ADOUOrGroup -Domain $Domain -Server $Server -Attribute $SamAccountName -ObjectType "group"
                        $DistinguishedName = $ADGroupObject.DistinguishedName
                        if($Clear) {
                            if ($ADGroupObject) {
                                Delete-ADObject -Domain $Domain -Server $Server -DistinguishedName $DistinguishedName -ObjectType "group"
                            }
                        } else {
                            Set-ADGroups -ADGroupObject $ADGroupObject -Domain $Domain -Server $Server -SamAccountName $SamAccountName -Name $Name -DisplayName $DisplayName -Description $Description -OU $OU -Update $Update
                        }
                    }
                }
            }
            
            if ($PSBoundParameters.ContainsKey("CSVFileUsersServices")) {
                $CSVUsersServices = Import-Csv -Path $CSVFileUsersServices -Delimiter $CSVDelimiter
                #####Creating/Updating HoneyUsers#####
                foreach ($dataUsersServices in $CSVUsersServices) {
                    $WhenCreated = $dataUsersServices.whenCreated
                    $Name = $dataUsersServices.name
                    $DisplayName = $dataUsersServices.displayName
                    $GivenName = $dataUsersServices.givenName
                    $Description = $dataUsersServices.description
                    $SamAccountName = $dataUsersServices.samAccountName
                    $Password =  (Convertto-SecureString -Force -AsPlainText $dataUsersServices.password)
                    $OU = $dataUsersServices.ou
                    $MemberOf = $dataUsersServices.memberOf
                    $PasswordNeverExpires = [System.Convert]::ToBoolean($dataUsersServices.passwordNeverExpires)
                    $DoesNotRequirePreAuth = [System.Convert]::ToBoolean($dataUsersServices.doesNotRequirePreAuth)
                    $TrustedForDelegation = [System.Convert]::ToBoolean($dataUsersServices.trustedForDelegation)
                    $Enabled = [System.Convert]::ToBoolean($dataUsersServices.enabled)
                    $UserPrincipalName = $dataUsersServices.userPrincipalName
                    $CustomAttribute = $dataUsersServices.customAttribute
                    $Domain = ($UserPrincipalName.split('@'))[1]   
                    $SPN = $dataUsersServices.spn

                    #####Checking if the domain user account exists or not#####
                    $ADUserObject = Get-ADUserOrComputerObject -SamAccountName $SamAccountName -Domain $Domain -Server $Server -ObjectType "user"

                    #####Removing or Creating/Updating the domain user accounts#####
                    if($Clear) {
                        if ($ADUserObject) {
                            $DistinguishedName = $ADUserObject.DistinguishedName
                            Delete-ADObject -Domain $Domain -Server $Server -DistinguishedName $DistinguishedName -ObjectType "user"
                        }
                    } else {
                        if (-Not $ADUserObject) {
                            $WhenCreatedTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (get-date $WhenCreated)).TotalMilliseconds
                            $CurrentTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (get-date)).TotalMilliseconds
                            if ($CurrentTimestamp -ge $WhenCreatedTimestamp) {
                                Set-ADUserObject -ADUserObject $false -Domain $Domain -Server $Server -SamAccountName $SamAccountName -Password $Password -Name $Name -DisplayName $DisplayName  `
                                -GivenName $GivenName -Description $Description -UserPrincipalName $UserPrincipalName -OU $OU `
                                -PasswordNeverExpires $PasswordNeverExpires -TrustedForDelegation $TrustedForDelegation -CustomAttribute $CustomAttribute  `
                                -Enabled $Enabled -Update $false
                            }
                        } else {
                            Set-ADUserObject -ADUserObject $ADUserObject -Domain $Domain -Server $Server -SamAccountName $SamAccountName -Password $Password -Name $Name -DisplayName $DisplayName  `
                            -GivenName $GivenName -Description $Description -UserPrincipalName $UserPrincipalName -OU $OU `
                            -PasswordNeverExpires $PasswordNeverExpires -TrustedForDelegation $TrustedForDelegation -CustomAttribute $CustomAttribute  `
                            -Enabled $Enabled -Update $Update
                        }  

                        #####Retrieving the domain user object#####
                        $ADUserObject = Get-ADUserOrComputerObject -SamAccountName $SamAccountName -Domain $Domain -Server $Server -ObjectType "user"
                      
                        #####Adding/Updating a domain user to one or more Active Directory groups#####
                        Set-ADUserOrComputerGroups -ADObject $ADUserObject -Domain $Domain -Server $Server -MemberOf $MemberOf -Update $Update
                        
                        #####Creating/Updating SPN#####
                        Set-ADSPNUserOrComputer -ADObject $ADUserObject -Domain $Domain -Server $Server -SPN $SPN -Update $Update -ObjectType "user"

                        #####Enabling/Disabling Kerberos pre-authentication which could allow AS-REP roasting attacks for a specific domain user account#####
                        Set-KerberosPreAuth -ADObject $ADUserObject -Domain $Domain -Server $Server -RequirePreAuth $DoesNotRequirePreAuth -Update $Update
                    }
                }
            }

            if ($PSBoundParameters.ContainsKey("CSVFileComputers")) {
                $CSVComputers = Import-Csv -Path $CSVFileComputers -Delimiter $CSVDelimiter
                #####Creating/Updating HoneyComputers#####
                foreach ($dataComputers in $CSVComputers) {
                    $WhenCreated = $dataComputers.whenCreated
                    $Name = $dataComputers.name
                    $DisplayName = $dataComputers.displayName
                    $Description = $dataComputers.description
                    $DNSHostName = $dataComputers.dNSHostName
                    $HomePage = $dataComputers.homePage
                    $Location = $dataComputers.location
                    $OperatingSystem = $dataComputers.operatingSystem
                    $OperatingSystemHotfix = $dataComputers.operatingSystemHotfix
                    $OperatingSystemServicePack = $dataComputers.operatingSystemServicePack
                    $OperatingSystemVersion = $dataComputers.operatingSystemVersion
                    $ManagedBy = $dataComputers.managedBy
                    $SamAccountName = $dataComputers.samAccountName
                    $Password =  (Convertto-SecureString -Force -AsPlainText $dataComputers.password)
                    $OU = $dataComputers.ou
                    $MemberOf = $dataComputers.memberOf
                    $PasswordNeverExpires = [System.Convert]::ToBoolean($dataComputers.passwordNeverExpires)
                    $DoesNotRequirePreAuth = [System.Convert]::ToBoolean($dataComputers.doesNotRequirePreAuth)
                    $TrustedForDelegation = [System.Convert]::ToBoolean($dataComputers.trustedForDelegation)
                    $Enabled = [System.Convert]::ToBoolean($dataComputers.enabled)
                    $KerberosEncryptionType = $dataComputers.kerberosEncryptionType
                    $UserPrincipalName = $dataComputers.userPrincipalName
                    $CustomAttribute = $dataComputers.customAttribute
                    $Domain = ($UserPrincipalName.split('@'))[1]   
                    $SPN = $dataComputers.spn

                    #####Checking if the domain computer account exists or not#####
                    $ADComputerObject = Get-ADUserOrComputerObject -Domain $Domain -Server $Server -SamAccountName $SamAccountName -ObjectType "computer"
                    
                    #####Removing or Creating/Updating the domain computer accounts#####
                    if($Clear) {
                        if ($ADComputerObject) {
                            $DistinguishedName = $ADComputerObject.DistinguishedName
                            Delete-ADObject -Domain $Domain -Server $Server -DistinguishedName $DistinguishedName -ObjectType "computer"
                        }
                    } else {
                        if (-Not $ADComputerObject) {
                            $WhenCreatedTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (get-date $WhenCreated)).TotalMilliseconds
                            $CurrentTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (get-date)).TotalMilliseconds
                            if ($CurrentTimestamp -ge $WhenCreatedTimestamp) {
                                Set-ADComputerObject -ADComputerObject $false -Name $Name -DisplayName $DisplayName -Description $Description -DNSHostName $DNSHostName `
                                -HomePage $HomePage -Location $Location -OperatingSystem $OperatingSystem -OperatingSystemHotfix $OperatingSystemHotfix -OperatingSystemServicePack $OperatingSystemServicePack `
                                -OperatingSystemVersion $OperatingSystemVersion -SamAccountName $SamAccountName -Password $Password -OU $OU -PasswordNeverExpires $PasswordNeverExpires `
                                -DoesNotRequirePreAuth $DoesNotRequirePreAuth -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -KerberosEncryptionType $KerberosEncryptionType -UserPrincipalName $UserPrincipalName `
                                -CustomAttribute $CustomAttribute -Domain $Domain -Server $Server -Update $false
                            }
                        } else {
                                Set-ADComputerObject -ADComputerObject $ADComputerObject -Name $Name -DisplayName $DisplayName -Description $Description -DNSHostName $DNSHostName `
                                -HomePage $HomePage -Location $Location -OperatingSystem $OperatingSystem -OperatingSystemHotfix $OperatingSystemHotfix -OperatingSystemServicePack $OperatingSystemServicePack `
                                -OperatingSystemVersion $OperatingSystemVersion -SamAccountName $SamAccountName -Password $Password -OU $OU -PasswordNeverExpires $PasswordNeverExpires `
                                -DoesNotRequirePreAuth $DoesNotRequirePreAuth -TrustedForDelegation $TrustedForDelegation -Enabled $Enabled -KerberosEncryptionType $KerberosEncryptionType -UserPrincipalName $UserPrincipalName `
                                -CustomAttribute $CustomAttribute -Domain $Domain -Server $Server -Update $Update
                        }

                        #####Retrieving the domain computer object#####
                        $ADComputerObject = Get-ADUserOrComputerObject -Domain $Domain -Server $Server -SamAccountName $SamAccountName -ObjectType "computer"

                        #####Setting 'ManagedBy' attribute for a specific domain computer account#####
                        Set-ADManagedByComputer -ADComputerObject $ADComputerObject -Domain $Domain -Server $Server -ManagedBy $ManagedBy

                        #####Adding/Updating a domain computer to one or more Active Directory groups#####
                        Set-ADUserOrComputerGroups -ADObject $ADComputerObject -Domain $Domain -Server $Server -MemberOf $MemberOf -Update $Update
                       
                        #####Creating/Updating SPN#####
                        Set-ADSPNUserOrComputer -ADObject $ADComputerObject -Domain $Domain -Server $Server -SPN $SPN -Update $Update -ObjectType "computer"

                        #####Enabling/Disabling Kerberos pre-authentication which could allow AS-REP roasting attacks for a specific domain computer account#####
                        Set-KerberosPreAuth -ADObject $ADComputerObject -Domain $Domain -Server $Server -RequirePreAuth $DoesNotRequirePreAuth -Update $Update
                    }
                }
            }

            if ($PSBoundParameters.ContainsKey("CSVFileACLS")) {
                $CSVACLS = Import-Csv -Path $CSVFileACLS -Delimiter $CSVDelimiter
                #####Creating/Updating or Removing ACLS for domain users or computers#####
                foreach ($dataACLS in $CSVACLS) {
                    $Domain = $dataACLS.domain
                    $SourceSamAccountName = $dataACLS.sourceSamAccountName
                    $TargetSamAccountName = $dataACLS.targetSamAccountName
                    $SourceObjectType = $dataACLS.sourceObjectType
                    $TargetObjectType = $dataACLS.targetObjectType
                    $ADRight = $dataACLS.adRight
                    $AccessType = $dataACLS.accessType
                    $SecurityInheritance = $dataACLS.securityInheritance
                    Set-ACLSObject -Domain $Domain -Server $Server -SourceSamAccountName $SourceSamAccountName -SourceObjectType $SourceObjectType -TargetSamAccountName $TargetSamAccountName -TargetObjectType $TargetObjectType `
                    -ADRight $ADRight -AccessType $AccessType -SecurityInheritance $SecurityInheritance -Update $Update -Clear $Clear
                }
            }

        } Catch {
            $Message = "[!] $(Get-DateTime): $_.Exception.Message"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    }
    end {}
}

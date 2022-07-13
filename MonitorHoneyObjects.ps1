<#
.SYNOPSIS
    Monitor HoneyUsers/HoneyServices, HoneyComputers objects, OU/Groups and ACLs.
.DESCRIPTION
    Monitor and Track Honeypot object changes.
.NOTE
    Version:        1.0
    Author:         @froyo75
    Creation Date:  22/06/2022
    Purpose/Change: 
        - 1.0 Initial script development
.EXAMPLE
    #To track changes of all HoneyUsers/HoneyServices objects specified within the CSV
    C:\PS> MonitorHoneyObjects -CSVDelimiter ';' -CSVFileOUGroups  C:\Users\Administrator\Desktop\OUGroups.csv -OutputFormat all -OutputFilePath Results

    #To track changes of all HoneyComputers objects specified within the CSV
    C:\PS> MonitorHoneyObjects -CSVDelimiter ';' -CSVFileUsersServices C:\Users\Administrator\Desktop\UsersServices.csv -OutputFormat csv,txt -OutputFilePath Results

    #To track changes of all OU/Groups objects specified within the CSV
    C:\PS> MonitorHoneyObjects -CSVDelimiter ';' -CSVFileComputers C:\Users\Administrator\Desktop\Computers.csv -OutputFormat gridview,txt,xml -OutputFilePath Results

    #To track changes of ACLs of a specified AD user, group or computer object specified within the CSV
    C:\PS> MonitorHoneyObjects -CSVDelimiter ';' -CSVFileACLS C:\Users\Administrator\Desktop\ACLS.csv -OutputFormat gridview -OutputFilePath Results
#>

$memberOfSeparator = '|'
$SPNSeparator = ","

#####Get the current date and time in specific format#####
function Get-DateTime() {
    return $(Get-Date -UFormat "%m/%d/%Y %T")
}

#####A Simple logging function#####
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

#####Generating output results in different formats like TXT, CSV, XML or display data as an interactive graphical table using "GridView"#####
function OutputResults([string]$ObjectType,[object]$ObjectList, [array]$OutputFormat, [string]$OutputFilePath) {
    Try {
        $ExtList = @('txt', 'csv', 'xml', 'log')
        $FileName = $OutputFilePath.split('\')[-1]
        $OutputBaseName = "$OutputFilePath"
        foreach ($Ext in $ExtList) {
            if ($FileName -Like "*.$Ext") {
                $OutputBaseName = "$OutputFilePath.TrimEnd($Ext)"
                break
            }
        }

        if ($OutputFormat.ToLower() -eq "all") { 
            OutputResults -ObjectType $ObjectType -ObjectList $ObjectList -OutputFormat txt -OutputFilePath $OutputFilePath
            OutputResults -ObjectType $ObjectType -ObjectList $ObjectList -OutputFormat csv -OutputFilePath $OutputFilePath
            OutputResults -ObjectType $ObjectType -ObjectList $ObjectList -OutputFormat xml -OutputFilePath $OutputFilePath
            OutputResults -ObjectType $ObjectType -ObjectList $ObjectList -OutputFormat gridview -OutputFilePath $OutputFilePath
        }

        $Suffix = $ObjectType.substring(0,1).toupper()+$ObjectType.substring(1).tolower()  + "s"
        $Title = "Audit - " + $Suffix

        foreach($Format in $OutputFormat.ToLower()) {
            switch ($Format) {
                gridview {
                     $ObjectList | Out-GridView -Title $Title
                }

                txt {
                    $ObjectList | Format-table -Property * | Out-File -FilePath "$OutputBaseName-$Suffix.txt"
                }

                csv {
                    $ObjectList | ConvertTo-Csv -NoTypeInformation -Delimiter $CSVDelimiter | Out-File "$OutputBaseName-$Suffix.csv"
                }

                xml {
                    $ObjectList | ConvertTo-Xml -NoTypeInformation -As String | Out-File "$OutputBaseName-$Suffix.xml"
                }
            }
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Creating a table-like custom objects for output results#####
function New-RowObject([string]$ObjectType){
    
    switch ($ObjectType) {
        user-computer {
            $RowProps = [ordered]@{
                "Object Type" = "N/A"
                Domain = "N/A"
                Enabled = "N/A"
                WhenCreated = "N/A"
                WhenChanged = "N/A"
                SamAccountName = "N/A"
                Name = "N/A"
                Groups = "N/A"
                OU = "N/A"
                LastLogonDate = "N/A"
                LastBadPasswordAttempt = "N/A"
                PasswordLastSet = "N/A"
                badPwdCount = "N/A"
                LockedOut = "N/A"
                SPNs = "N/A"
                DoesNotRequirePreAuth = "N/A"
                TrustedForDelegation = "N/A"
            }
        }

        ou-group {
            $RowProps = [ordered]@{
                "Object Type" = "N/A"
                Status = "N/A"
                Domain = "N/A"
                Name = "N/A"
                DisplayName = "N/A"
                SamAccountName = "N/A"
                OU = "N/A"
            }
        }

        acl {
            $RowProps = [ordered]@{
                Status = "N/A"
                Domain = "N/A"
                sourceSamAccountName = "N/A"
                targetSamAccountName = "N/A"
                ActiveDirectoryRights = "N/A"
                AccessControlType = "N/A"
                InheritanceType = "N/A"
            }
        }

    }

    $RowObject = New-Object -TypeName PSObject -Property $RowProps
    return $RowObject
}

#####Creating a table-like custom objects from a CSV file#####
function ParseCSVFile([string]$CSVDelimiter, [string]$CSVFile, [string]$ObjectType) {
    Try {
        $CSVObjectList = Import-Csv -Path $CSVFile -Delimiter $CSVDelimiter
        $DataObjectList = New-Object System.Collections.ArrayList

        foreach ($CSVObject in $CSVObjectList) {
            switch ($ObjectType) {
                user-service {
                    $DataObject = New-Object -TypeName PSObject -Property @{
                        WhenCreated = $CSVObject.whenCreated
                        Name = $CSVObject.name
                        DisplayName = $CSVObject.displayName
                        GivenName = $CSVObject.givenName
                        Description = $CSVObject.description
                        SamAccountName = $CSVObject.samAccountName
                        Password =  (Convertto-SecureString -Force -AsPlainText $CSVObject.password)
                        OU = $CSVObject.ou
                        MemberOf = $CSVObject.memberOf
                        PasswordNeverExpires = [System.Convert]::ToBoolean($CSVObject.passwordNeverExpires)
                        DoesNotRequirePreAuth = [System.Convert]::ToBoolean($CSVObject.doesNotRequirePreAuth)
                        TrustedForDelegation = [System.Convert]::ToBoolean($CSVObject.trustedForDelegation)
                        Enabled = [System.Convert]::ToBoolean($CSVObject.enabled)
                        UserPrincipalName = $CSVObject.userPrincipalName
                        CustomAttribute = $CSVObject.customAttribute
                        Domain = ($CSVObject.userPrincipalName.split('@'))[1]
                        SPN = $CSVObject.spn
                    }
                }

                computer {
                    $DataObject = New-Object -TypeName PSObject -Property @{
                        WhenCreated = $CSVObject.whenCreated
                        Name = $CSVObject.name
                        DisplayName = $CSVObject.displayName
                        Description = $CSVObject.description
                        DNSHostName = $CSVObject.dNSHostName
                        HomePage = $CSVObject.homePage
                        Location = $CSVObject.location
                        OperatingSystem = $CSVObject.operatingSystem
                        OperatingSystemHotfix = $CSVObject.operatingSystemHotfix
                        OperatingSystemServicePack = $CSVObject.operatingSystemServicePack
                        OperatingSystemVersion = $CSVObject.operatingSystemVersion
                        ManagedBy = $CSVObject.managedBy
                        SamAccountName = $CSVObject.samAccountName
                        Password =  (Convertto-SecureString -Force -AsPlainText $CSVObject.password)
                        OU = $CSVObject.ou
                        MemberOf = $CSVObject.memberOf
                        PasswordNeverExpires = [System.Convert]::ToBoolean($CSVObject.passwordNeverExpires)
                        DoesNotRequirePreAuth = [System.Convert]::ToBoolean($CSVObject.doesNotRequirePreAuth)
                        TrustedForDelegation = [System.Convert]::ToBoolean($CSVObject.trustedForDelegation)
                        Enabled = [System.Convert]::ToBoolean($CSVObject.enabled)
                        KerberosEncryptionType = $CSVObject.kerberosEncryptionType
                        UserPrincipalName = $CSVObject.userPrincipalName
                        CustomAttribute = $CSVObject.customAttribute
                        Domain = ($CSVObject.userPrincipalName.split('@'))[1]   
                        SPN = $CSVObject.spn
                    }
                }

                ou-group {
                    $DataObject = New-Object -TypeName PSObject -Property @{
                        ObjectType = $CSVObject.objectType
                        Domain = $CSVObject.domain
                        Name = $CSVObject.name
                        DisplayName = $CSVObject.displayName
                        Description = $CSVObject.description
                        SamAccountName = $CSVObject.samAccountName
                        OU = $CSVObject.ou
                    }
                }

                acl {
                    $DataObject = New-Object -TypeName PSObject -Property @{
                        Domain = $CSVObject.domain
                        SourceSamAccountName = $CSVObject.sourceSamAccountName
                        TargetSamAccountName = $CSVObject.targetSamAccountName
                        SourceObjectType = $CSVObject.sourceObjectType
                        TargetObjectType = $CSVObject.targetObjectType
                        ADRight = $CSVObject.adRight
                        AccessType = $CSVObject.accessType
                        SecurityInheritance = $CSVObject.securityInheritance
                    }
                }
            }
            [Void]$DataObjectList.Add($DataObject)
        }
        return $DataObjectList
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Retrieving the domain user or computer object properties#####
function Get-ADUserOrComputerObject([string]$Server, [string]$Domain, [string]$SamAccountName, [string]$ObjectType) {
    Try {
        if ($ObjectType -like "user-service") {
            $ADObject = (Get-ADUser -Server $Server -Identity $SamAccountName -Properties *)
        } elseif ($ObjectType -like "computer") {
            $ADObject = (Get-ADComputer -Server $Server -Identity $SamAccountName -Properties *)
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

#####Retrieving the domain OU or group object properties#####
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

#####Checking whether a user or a computer belongs to a specific group#####
function Check-ADUserOrComputerInGroup([string]$SamAccountName, [string]$Server, [string]$Domain, [string]$Group) {
    Try {
        $Exist = [bool](Get-ADGroupMember -Server $Server -Identity $Group | ? {$_.SamAccountName -eq $SamAccountName})
        if (-Not $Exist) {
            $Message = "[*] $(Get-DateTime): The domain object '$Domain\$SamAccountName' does not belong to the '$Group' group !"
            Logging -Message $Message -Color "magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        return $Exist
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

#####Checking whether or not the AD object exists or the object is missing or if the object is not created yet#####
function CheckWhenCreated([string]$Domain, [object]$CSVObject, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $CSVObject.SamAccountName
        $WhenCreatedTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (Get-Date $CSVObject.WhenCreated)).TotalMilliseconds
        $CurrentTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (Get-Date)).TotalMilliseconds
        if (-Not $ADObject) {
            if ($CurrentTimestamp -ge $WhenCreatedTimestamp) {
                $Status = "Missing Entry"
                $Message = "[!] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' is missing or has been deleted !"
                Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            } else {
                $Status = "Not Created Yet"
                $Message = "[*] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' has not been created yet !"
                Logging -Message $Message -Color "magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            }
        } else {
            $Status = $ADObject.WhenCreated
            $Message = "[+] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' has been created on '$Status'."
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        return $Status
     } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the password if it has already expired or the password has never changed since the creation of the AD object#####
function CheckPasswordLastSet([string]$Domain, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $WhenCreatedTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (Get-Date $ADObject.WhenCreated)).TotalMinutes
        $PasswordLastSetTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (Get-Date $ADObject.PasswordLastSet)).TotalMinutes
        $MaxPasswordAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
        $PasswordExpiredDateTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (($ADObject.PasswordLastSet).AddDays($MaxPasswordAge))).TotalMinutes
        if ($PasswordLastSetTimestamp -eq $WhenCreatedTimestamp) {
            $Status = "Never Changed"
            $Message = "[*] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' password has never changed !"
            Logging -Message $Message -Color "magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } elseif ((-Not $ADObject.PasswordNeverExpires) -and ($PasswordLastSetTimestamp -gt $PasswordExpiredDateTimestamp)) {
            $Status = "Password expired"
            $Message = "[!] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' password has expired !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $Status = $ADObject.PasswordLastSet
            $Message = "[+] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' password has been changed on '$Status'."
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the AD object has already logged in#####
function CheckLastLogon([string]$Domain, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        if ($ADObject.LastLogonDate -eq $null) {
            $Status = "Never Logged in"
            $Message = "[*] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' password has never logged in !"
            Logging -Message $Message -Color "magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $Status = $ADObject.LastLogonDate
            $Message = "[+] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' password has logged in $Status."
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the AD object is locked out or if it has never performed unsuccessful login attempts#####
function CheckLastBadPasswordAttemptOrLockedOut([string]$Domain, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $LockedOut = $ADObject.LockedOut
        if ($LockedOut) {
            $LockedStatus  = "Locked Out"
            $Message = "[!] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' is locked out !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $LockedStatus = $LockedOut
        }
        if ($ADObject.LastBadPasswordAttempt -eq $null) {
            $LastBadPasswordAttempt = "Never had a Failed Login"
            $Message = "[*] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' has never performed unsuccessful login attempts !"
            Logging -Message $Message -Color "magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $LastBadPasswordAttempt =  $ADObject.LastBadPasswordAttempt
        }
        return $LockedStatus, $LastBadPasswordAttempt
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the AD object is enabled or not#####
function CheckEnabledOrDisabled([string]$Domain, [object]$CSVObject, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $CSVEnabled = $CSVObject.Enabled
        $ADEnabled = $ADObject.Enabled
        if ($CSVEnabled -eq $ADEnabled) {
            $Status = $ADEnabled
            $Message = "[+] $(Get-DateTime): The domain $ObjectType '$Domain\$SamAccountName' is '$Status' within the domain '$Domain' !"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $Status = "CSV/AD Values Mismatch"
            $Message = "[!] $(Get-DateTime): AD Object enabed/disabled -> CSV:{$CSVEnabled} / AD:{$ADEnabled} values mismatch error for the domain $ObjectType '$Domain\$SamAccountName' !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } 
        return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the AD object is configured to not require Kerberos Pre-Authentication#####
function CheckDoesNotRequirePreAuth([string]$Domain, [object]$CSVObject, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $CSVDoesNotRequirePreAuth = $CSVObject.DoesNotRequirePreAuth
        $ADDoesNotRequirePreAuth = $ADObject.DoesNotRequirePreAuth
        if ($CSVDoesNotRequirePreAuth -eq $ADDoesNotRequirePreAuth) {
            $Status = $ADDoesNotRequirePreAuth
            $Message = "[+] $(Get-DateTime): Kerberos pre-authentication setting set to '$Status' for the domain $ObjectType '$Domain\$SamAccountName'."
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $Status = "CSV/AD Values Mismatch"
            $Message = "[!] $(Get-DateTime): DoesNotRequirePreAuth -> CSV:{$CSVDoesNotRequirePreAuth} / AD:{$ADDoesNotRequirePreAuth} values mismatch error for the domain $ObjectType '$Domain\$SamAccountName' !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } 
        return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the AD object is trusted for delegation#####
function CheckTrustedForDelegation([string]$Domain, [object]$CSVObject, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $CSVTrustedForDelegation = $CSVObject.TrustedForDelegation
        $ADDTrustedForDelegation = $ADObject.TrustedForDelegation
        if ($CSVTrustedForDelegation -eq $ADDTrustedForDelegation) {
            $Status = $ADDTrustedForDelegation
            $Message = "[+] $(Get-DateTime): Trusted for Delegation setting set to '$Status' for the domain $ObjectType '$Domain\$SamAccountName'."
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $Status = "CSV/AD Values Mismatch"
            $Message = "[!] $(Get-DateTime): TrustedForDelegation -> CSV:{$CSVTrustedForDelegation} / AD:{$ADDTrustedForDelegation} values mismatch error for the domain $ObjectType '$Domain\$SamAccountName' !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } 
        return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether SPNs are correctly set for the AD object#####
function CheckSPNs([string]$Domain, [object]$CSVObject, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $CSVSPNs = $CSVObject.SPN
        $ADSPNs = $ADObject.ServicePrincipalNames
        if (($CSVSPNs -eq "None") -and ($ADSPNs.Count -eq 0)) {
            $Status = "OK"
            $Message = "[+] $(Get-DateTime): No SPN(s) are set for the domain object '$Domain\$SamAccountName'."
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $CSVSPNList = $CSVSPNs.Split($SPNSeparator) | % { $_.Replace("'","").Trim() }
            $ADSPNList = $ADSPNs | % { $_ }    
            $Result = Compare-Object $CSVSPNList $ADSPNList
            $SPNList = ($ADSPNList | % { "'$_'" } | out-string).Replace("`n",",").TrimEnd(',')
            if ($Result -eq $Null) {
                $Status = "OK"
                $Message = "[+] $(Get-DateTime): The following SPN(s) {$SPNList} are set for the domain object '$Domain\$SamAccountName'."
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            } else {
                $Status = "CSV/AD Values Mismatch"
                $Message = "[!] $(Get-DateTime): SPN(s) ->  CSV:{$CSVSPNs} / AD:{$SPNList} values mismatch error for the domain $ObjectType '$Domain\$SamAccountName' !"
                Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            }
        }
      return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether groups are correctly set for the AD object#####
function CheckADObjectGroups([string]$Domain, [object]$CSVObject, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $CSVMemberOf = $CSVObject.MemberOf
        $Status = "OK"
        if (($CSVMemberOf -ne "") -and ($CSVMemberOf -ne "None")) {
            $MemberOfArray = $CSVMemberOf.split($memberOfSeparator)
            foreach ($Group in $MemberOfArray) {
                if ($Group -ne "") {
                    $ExistInGroup = Check-ADUserOrComputerInGroup -SamAccountName $ADObject.SamAccountName -Domain $Domain -Server $Server -Group $Group
                    if (-Not $ExistInGroup) {
                        $Status = "NOK"
                        $Message = "[!] $(Get-DateTime): The domain object '$Domain\$SamAccountName' does not belong to the '$Group' group !"
                        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    } else {
                        $Message = "[+] $(Get-DateTime): The domain object '$Domain\$SamAccountName' belongs to the '$Group' group."
                        Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    }
                }
            }
        }
        return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the AD object belongs to the correct OU#####
function CheckADObjectOU([string]$Domain, [object]$CSVObject, [object]$ADObject, [string]$ObjectType) {
    Try {
        $SamAccountName = $ADObject.SamAccountName
        $CSVOU = $CSVObject.OU
        $ADOU = $ADObject.DistinguishedName.Split(",",2)[1]
        if ($CSVOU -eq $ADOU) {
            $Status = "OK"
            $Message = "[+] $(Get-DateTime): The domain object '$Domain\$SamAccountName' belongs to the '$ADOU' Organizational Unit."
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $Status = "CSV/AD Values Mismatch"
            $Message = "[!] $(Get-DateTime): OU ->  CSV:{$CSVOU} / AD:{$ADOU} values mismatch error for the domain $ObjectType '$Domain\$SamAccountName' !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        return $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether the OU or Group exists or not#####
function CheckOUGroups([string]$Domain, [object]$CSVObject, [string]$ObjectType) {
    Try {
        $CSVName = $CSVObject.Name
        $CSVOU = $CSVObject.OU
        if ($ObjectType -eq "ou") {
            $Attribute = "OU=$CSVName,$CSVOU"
            $ADObject = Get-ADOUOrGroup -Domain $Domain -Server $Server -Attribute $Attribute -ObjectType "ou"
        } elseif($ObjectType -eq "group") {
            $Attribute = $CSVObject.SamAccountName
            $ADObject = Get-ADOUOrGroup -Domain $Domain -Server $Server -Attribute $Attribute -ObjectType "group"
        }
        if (-Not $ADObject) {
            $Status = "Missing Entry"
            $CurrentOU = $CSVOU
            $Message = "[!] $(Get-DateTime): The $ObjectType '$Attribute' is missing within the domain '$Domain' !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $ADOU = $ADObject.DistinguishedName.Split(",",2)[1]
            $Status = "OK"
            $Message = "[+] $(Get-DateTime): The $ObjectType '$Attribute' exists within the domain '$Domain' !"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            if ($ObjectType -eq "group") {
                if ($CSVOU -eq $ADOU) {
                    $Message = "[+] $(Get-DateTime): The domain $ObjectType '$Domain\$Attribute' belongs to the '$ADOU' Organizational Unit."
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                } else {
                    $Status = "CSV/AD Values Mismatch"
                    $Message = "[!] $(Get-DateTime): OU ->  CSV:{$CSVOU} / AD:{$ADOU} values mismatch error for the domain $ObjectType '$Domain\$Attribute' !"
                    Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                }
            } 
            $CurrentOU = $ADOU
        }
        return $CurrentOU, $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Checking whether ACLs are correctly set for the AD object#####
function CheckACLs([string]$Domain, [object]$CSVObject, [object]$ADObject) {
    Try {
        $SourceSamAccountName = $CSVObject.sourceSamAccountName
        $TargetSamAccountName = $CSVObject.targetSamAccountName
        $TargetIdentityReference = (($Domain.split('.')[0]).ToUpper()) + '\' + $TargetSamAccountName
        if (-Not $ADObject) {
            $Status = "Missing Entry"
            $Attribute = $CSVObject.sourceSamAccountName
            $ObjectType = $CSVObject.sourceObjectType
            $Message = "[!] $(Get-DateTime): The $ObjectType '$Attribute' is missing within the domain '$Domain' !"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        } else {
            $SourceDistinguishedName = $ADObject.DistinguishedName
            $CurrentADObjectACLs = (Get-Acl "AD:$SourceDistinguishedName").Access | ? {$_.IdentityReference -like $TargetIdentityReference}
            $CSVObjectACLs = [PSCustomObject][ordered]@{
                ActiveDirectoryRights = $CSVObject.adRight
                AccessControlType = $CSVObject.accessType
                InheritanceType = $CSVObject.securityInheritance
            }
            $CurrentACLs = $CSVObjectACLs
            if ($CurrentADObjectACLs) {
                $ADObjectACLs = [PSCustomObject][ordered]@{
                    ActiveDirectoryRights = "$($CurrentADObjectACLs.ActiveDirectoryRights)"
                    AccessControlType = "$($CurrentADObjectACLs.AccessControlType)"
                    InheritanceType = "$($CurrentADObjectACLs.InheritanceType)"
                }
                $Result = Compare-Object $CSVObjectACLs.PSObject.Properties $ADObjectACLs.PSObject.Properties
                if ($Result -eq $Null) {
                    $Status = "OK"
                    $Message = "[+] $(Get-DateTime): ACLs -> The identity reference '$TargetIdentityReference' exists on '$SourceDistinguishedName' object."
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                } else {
                    $CurrentACLs = $CurrentADObjectACLs
                    $Status = "NOK"
                    $Status = "CSV/AD Values Mismatch"
                    $Message = "[!] $(Get-DateTime): ACLs ->  CSV:{ActiveDirectoryRights=$($CSVObjectACLs.ActiveDirectoryRights),AccessControlType=$($CSVObjectACLs.AccessControlType),InheritanceType=$($CSVObjectACLs.InheritanceType)} / AD:{ActiveDirectoryRights=$($ADObjectACLs.ActiveDirectoryRights),AccessControlType=$($ADObjectACLs.AccessControlType),InheritanceType=$($ADObjectACLs.InheritanceType)} values mismatch error for the domain $ObjectType '$Domain\$SourceSamAccountName' !"
                    Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                }
            } else {
                $Status = "ACL Not Found"
                $Message = "[!] $(Get-DateTime): ACLs -> The identity reference '$TargetIdentityReference' does not exist on '$SourceDistinguishedName' object."
                Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            }
        }
        return $CurrentACLs, $Status
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Track changes of all HoneyUsers/HoneyServices objects#####
function AuditUsersServices([object]$DataObjectList, [string]$Server) {
    Try {
        $GridObjectList = New-Object System.Collections.ArrayList
        Foreach ($CSVObject in $DataObjectList) {
            $UserPrincipalName = $CSVObject.UserPrincipalName
            $Domain = ($UserPrincipalName.split('@'))[1]
            $RowObject = New-RowObject -ObjectType "user-computer"
            $RowObject."Object Type" = "User-Service"
            $RowObject.Domain = $Domain
            $RowObject.SamAccountName = $CSVObject.SamAccountName
            $RowObject.Name = $CSVObject.Name
            $ADObject = Get-ADUserOrComputerObject -Server $Server -Domain $Domain -SamAccountName $CSVObject.SamAccountName -ObjectType "user-service"
            $RowObject.WhenCreated = CheckWhenCreated -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
            if ($ADObject) {
                $RowObject.PasswordLastSet = CheckPasswordLastSet -Domain $Domain -ADObject $ADObject -ObjectType "user-service"
                $RowObject.LastLogonDate = CheckLastLogon -Domain $Domain -ADObject $ADObject -ObjectType "user-service"
                $LockedStatus, $LastBadPasswordAttempt = CheckLastBadPasswordAttemptOrLockedOut -Domain $Domain -ADObject $ADObject -ObjectType "user-service"
                $RowObject.LastBadPasswordAttempt = $LastBadPasswordAttempt
                $RowObject.LockedOut = $LockedStatus
                $RowObject.Enabled = CheckEnabledOrDisabled -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
                $RowObject.DoesNotRequirePreAuth = CheckDoesNotRequirePreAuth -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
                $RowObject.TrustedForDelegation = CheckTrustedForDelegation -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
                $RowObject.SPNS = CheckSPNs -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
                $RowObject.Groups = CheckADObjectGroups -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
                $RowObject.OU = CheckADObjectOU -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
                $RowObject.WhenChanged = $ADObject.whenChanged
                $RowObject.badPwdCount = $ADObject.badPwdCount
            }
            [Void]$GridObjectList.Add($RowObject)
        }
        return $GridObjectList
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Track changes of all HoneyComputers objects#####
function AuditComputers([object]$DataObjectList, [string]$Server) {
    Try {
        $GridObjectList = New-Object System.Collections.ArrayList
        Foreach ($CSVObject in $DataObjectList) {
            $UserPrincipalName = $CSVObject.UserPrincipalName
            $Domain = ($UserPrincipalName.split('@'))[1]
            $RowObject = New-RowObject -ObjectType "user-computer"
            $RowObject."Object Type" = "Computer"
            $RowObject.Domain = $Domain
            $RowObject.SamAccountName = $CSVObject.SamAccountName
            $RowObject.Name = $CSVObject.Name
            $ADObject = Get-ADUserOrComputerObject -Server $Server -Domain $Domain -SamAccountName $CSVObject.SamAccountName -ObjectType "computer"
            $RowObject.WhenCreated = CheckWhenCreated -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "computer"
            if ($ADObject) {
                $RowObject.PasswordLastSet = CheckPasswordLastSet -Domain $Domain -ADObject $ADObject -ObjectType "computer"
                $RowObject.LastLogonDate = CheckLastLogon -Domain $Domain -ADObject $ADObject -ObjectType "computer"
                $LockedStatus, $LastBadPasswordAttempt = CheckLastBadPasswordAttemptOrLockedOut -Domain $Domain -ADObject $ADObject -ObjectType "computer"
                $RowObject.LastBadPasswordAttempt = $LastBadPasswordAttempt
                $RowObject.LockedOut = $LockedStatus
                $RowObject.Enabled = CheckEnabledOrDisabled -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "user-service"
                $RowObject.DoesNotRequirePreAuth = CheckDoesNotRequirePreAuth -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "computer"
                $RowObject.TrustedForDelegation = CheckTrustedForDelegation -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "computer"
                $RowObject.SPNS = CheckSPNs -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "computer"
                $RowObject.Groups = CheckADObjectGroups -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "computer"
                $RowObject.OU = CheckADObjectOU -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject -ObjectType "computer"
                $RowObject.WhenChanged = $ADObject.whenChanged
                $RowObject.badPwdCount = $ADObject.badPwdCount
            }
            [Void]$GridObjectList.Add($RowObject)
        }
        return $GridObjectList
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Track changes of all OU/Groups objects#####
function AuditOUGroups([object]$DataObjectList, [string]$Server) {
    Try {
        $GridObjectList = New-Object System.Collections.ArrayList
        Foreach ($CSVObject in $DataObjectList) {
            $Domain = $CSVObject.Domain
            $ObjectType = $CSVObject.ObjectType
            $RowObject = New-RowObject -ObjectType "ou-group"
            $RowObject."Object Type" = $ObjectType
            $RowObject.Domain = $Domain
            $RowObject.Name = $CSVObject.Name
            $RowObject.DisplayName = $CSVObject.DisplayName
            $SamAccountName = $CSVObject.SamAccountName
            if ($SamAccountName -ne "") {
                $RowObject.SamAccountName = $SamAccountName
            }
            $RowObject.OU = $CSVObject.OU
            $CurrentOU, $Status = CheckOUGroups -Domain $Domain -CSVObject $CSVObject -ObjectType $ObjectType
            $RowObject.OU = $CurrentOU
            $RowObject.Status = $Status
            [Void]$GridObjectList.Add($RowObject)
        }
        return $GridObjectList
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

#####Track changes of ACLs of a specified AD user, group or computer object#####
function AuditACLs([object]$DataObjectList, [string]$Server) {
    Try {
        $GridObjectList = New-Object System.Collections.ArrayList
        Foreach ($CSVObject in $DataObjectList) {
            $Domain = $CSVObject.Domain
            $ObjectType = $CSVObject.sourceObjectType
            if ($ObjectType -eq "group") {
                $Attribute = $CSVObject.sourceSamAccountName
                $ADObject = Get-ADOUOrGroup -Domain $Domain -Server $Server -Attribute $Attribute -ObjectType "group"
            } elseif($ObjectType -eq "user") {
                $ADObject = Get-ADUserOrComputerObject -Server $Server -Domain $Domain -SamAccountName $CSVObject.sourceSamAccountName -ObjectType "user-service"
            } else {
                $ADObject = Get-ADUserOrComputerObject -Server $Server -Domain $Domain -SamAccountName $CSVObject.sourceSamAccountName -ObjectType "computer"
            }
            $RowObject = New-RowObject -ObjectType "acl"
            $RowObject.Domain = $Domain
            $RowObject.sourceSamAccountName = $CSVObject.sourceSamAccountName 
            $RowObject.targetSamAccountName = $CSVObject.targetSamAccountName  
            $CurrentACLs, $Status = CheckACLs -Domain $Domain -CSVObject $CSVObject -ADObject $ADObject
            $RowObject.ActiveDirectoryRights = $CurrentACLs.ActiveDirectoryRights
            $RowObject.AccessControlType = $CurrentACLs.AccessControlType
            $RowObject.InheritanceType = $CurrentACLs.InheritanceType
            $RowObject.Status = $Status
            [Void]$GridObjectList.Add($RowObject)
        }
        return $GridObjectList
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Add-content $LogFile -value $Message
        Write-Host $Message -foregroundcolor "red"
    }
}

function MonitorHoneyObjects
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
                    HelpMessage="Specify the input CSV file for tracking changes of users, services objects.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFileUsersServices,

        [Parameter(Mandatory=$false,
                    HelpMessage="Specify the input CSV file for tracking changes of OU and Group objects.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFileOUGroups,

        [Parameter(Mandatory=$false,
                    HelpMessage="Specify the input CSV file for tracking changes of computer objects.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFileComputers,

        [Parameter(Mandatory=$false,
                    HelpMessage="Specify the input CSV file for tracking changes of the security descriptors of a specified AD object.")]
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
                    HelpMessage="Specify the format of the output file (e.g. txt, csv or xml) or send output to an interactive table using 'gridview' (Default=all).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("all", "gridview", "txt", "csv", "xml")]
        [array]$OutputFormat = "all",

        [Parameter(Mandatory=$false,
                    HelpMessage="Specify the file path to write output results in different formats like txt, csv or xml (Default=Results).")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFilePath = "$PSScriptRoot\Results",

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
        [bool]$DisplayMessage = $true
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
                $ObjectType = "ou-group"
                $DataOUGroups = ParseCSVFile -CSVDelimiter $CSVDelimiter -CSVFile $CSVFileOUGroups -ObjectType $ObjectType
                $OUGroupsObjectList = AuditOUGroups -DataObjectList $DataOUGroups -Server $Server
                OutputResults -ObjectType $ObjectType -ObjectList $OUGroupsObjectList -OutputFormat $OutputFormat -OutputFilePath $OutputFilePath
            }
            
            if ($PSBoundParameters.ContainsKey("CSVFileUsersServices")) {
                $ObjectType = "user-service"
                $DataUsersServices = ParseCSVFile -CSVDelimiter $CSVDelimiter -CSVFile $CSVFileUsersServices -ObjectType $ObjectType
                $UsersServicesObjectList = AuditUsersServices -DataObjectList $DataUsersServices -Server $Server
                OutputResults -ObjectType $ObjectType -ObjectList $UsersServicesObjectList -OutputFormat $OutputFormat -OutputFilePath $OutputFilePath
            }

            if ($PSBoundParameters.ContainsKey("CSVFileComputers")) {
                $ObjectType = "computer"
                $DataComputers = ParseCSVFile -CSVDelimiter $CSVDelimiter -CSVFile $CSVFileComputers -ObjectType $ObjectType
                $ComputersObjectList = AuditComputers -DataObjectList $DataComputers -Server $Server
                OutputResults -ObjectType $ObjectType -ObjectList $ComputersObjectList -OutputFormat $OutputFormat -OutputFilePath $OutputFilePath
            }

            if ($PSBoundParameters.ContainsKey("CSVFileACLS")) {
                $ObjectType = "acl"
                $DataACLs = ParseCSVFile -CSVDelimiter $CSVDelimiter -CSVFile $CSVFileACLS -ObjectType $ObjectType
                $ACLSObjectList = AuditACLs -DataObjectList $DataACLs -Server $Server
                OutputResults -ObjectType $ObjectType -ObjectList $ACLSObjectList -OutputFormat $OutputFormat -OutputFilePath $OutputFilePath
            }

        } Catch {
            $Message = "[!] $(Get-DateTime): $_.Exception.Message"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    }
    end {}
}

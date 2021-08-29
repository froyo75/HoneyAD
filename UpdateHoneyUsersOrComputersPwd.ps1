<#
.SYNOPSIS
    Update the HoneyUsers/Services or HoneyComputers' password automatically 
.DESCRIPTION
    Change the HoneyUsers/Services or HoneyComputers' password by updating automatically the "pwdLastSet" attribute when it is expired
    Changing computer password object require "Reset Password" permission !
.NOTES
    Version:        1.5
    Author:         @froyo75
    Creation Date:  02/09/2020
    Purpose/Change: 
        - 1.0 Initial script development
        - 1.1 Logging improvements
        - 1.2 Add Computer objects support + some major fixes and improvements
        - 1.3 Add CSV delimiter option
        - 1.4 Add/Fix 'Domain/Server' support
        - 1.5 Fix 'Set-ADPassword' issues
.EXAMPLE
    C:\PS> UpdateHoneyUsersOrComputersPwd -CSVFile C:\Users\Administrator\Desktop\RS\UsersServices.csv -ObjectType user -PassLength 40 -Delay 5
    C:\PS> UpdateHoneyUsersOrComputersPwd -CSVFile C:\Users\Administrator\Desktop\RS\UsersServices.csv -ObjectType user -PassLength 40 -Delay 5 -ForceUpdate $true
    C:\PS> UpdateHoneyUsersOrComputersPwd -CSVFile C:\Users\Administrator\Desktop\RS\Computers-TEST.csv -ObjectType computer -PassLength 40 -Delay 1 -ForceUpdate $true
#>

#$ErrorActionPreference = 'SilentlyContinue'
$PassCharset = 'ABCDEFGHKLMNOPRSTUVWXYZabcdefghiklmnoprstuvwxyz1234567890!-$%&/()=?}][{@#*+'
$defaultPDC = (Get-ADDomain).pdcEmulator

function Get-DateTime() {
    return $(Get-Date -UFormat '%m/%d/%Y %T')
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

function Get-PasswordLastSet([object]$ADObject) {
    Try {
        if ($ADObject) {
            $SamAccountName = $ADObject.SamAccountName
            $PasswordLastSet = $ADObject.passwordLastSet.DateTime
            $TimeStamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (get-date $PasswordLastSet)).TotalSeconds
            return $TimeStamp
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Get-RandomCharacters([int]$length, [string]$characters) { 
    Try {
        $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
        $private:ofs="" #https://devblogs.microsoft.com/powershell/psmdtagfaq-what-is-ofs/
        $randomPassword = [String]$characters[$random]
        $characterArray = $randomPassword.ToCharArray()   
        $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
        $outputString = -join $scrambledStringArray
        return $outputString 
    } Catch {
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    }
}

function Update-CSV([array]$CSVo, [string]$CSVFile, [string]$CSVDelimiter) {
    Try {
        $HashKeysArray = New-Object System.Collections.ArrayList($null)
        foreach($DataObject in $CSVo) {
            $CSVDataArray = New-Object System.Collections.ArrayList($null)
            $HashTableOfData = [ordered]@{}
            $DataObject.psobject.properties | Foreach { $HashTableOfData[$_.Name] = $_.Value }
            if ($HashKeysArray.Count -eq 0) {
                $HashKeysArray = $HashTableOfData.keys
                $CSVHeaders = $HashKeysArray -join $CSVDelimiter
                Set-Content $CSVFile -Value $CSVHeaders 
            }
            foreach($HasKey in $HashKeysArray) {
                if($HasKey -like "memberOf" -or $HasKey -like "spn" -or $HasKey -like "ou" -or $HasKey -like "managedBy" -or $HasKey -like "kerberosEncryptionType") {
                    $HashValue = $HashTableOfData[$HasKey].Insert($HashTableOfData[$HasKey].length,'"').Insert(0,'"')
                } else {
                    $HashValue = $HashTableOfData[$HasKey]
                }
                $CSVDataArray.Add($HashValue)
            }
            $CSVRow = $CSVDataArray -join $CSVDelimiter
            Add-Content $CSVFile -Value $CSVRow
        }
        $ExitCode = $?
        return $ExitCode
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function Set-ADPassword([string]$SamAccountName, [string]$CurrentPassword, [string]$NewPassword, [string]$Server, [string]$Domain, [string]$ObjectType) {
    $ExitCode = 1
    Try {
        $DomainAccount = "$Domain\$SamAccountName"
        $CurrentSecureStringPassword = (ConvertTo-SecureString -AsPlainText -Force $CurrentPassword)
        $NewSecureStringPassword = (ConvertTo-SecureString -AsPlainText -Force $NewPassword)
        $CredentialObject = New-Object System.Management.Automation.PSCredential($DomainAccount,$CurrentSecureStringPassword)
        if ($ObjectType -like "user") {
            $PassThruObject = Set-ADAccountPassword -PassThru -Identity $SamAccountName -Server $Server -Credential $CredentialObject -OldPassword $CurrentSecureStringPassword -NewPassword $NewSecureStringPassword
        } elseif ($ObjectType -like "computer") {
            $PassThruObject = Set-ADAccountPassword -PassThru -Identity $SamAccountName -Server $Server -Reset -NewPassword $NewSecureStringPassword
        }
        if($PassThruObject) { $ExitCode = 0 }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
    return $ExitCode
}

function Gen-NewPassword([array]$CSVo, [string]$CSVFile, [object]$ADObject, [string]$CurrentPassword, [string]$Server, [string]$Domain, [string]$ObjectType, [string]$CSVDelimiter, [boolean]$ForceUpdate) {
    Try {
        if ($ADObject) {
            $SamAccountName = $ADObject.SamAccountName
            $Message = "[+] $(Get-DateTime): Checking if the password of the $ObjectType '$Domain\$SamAccountName' will expire soon"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            $TimestampPasswordLastSet = Get-PasswordLastSet -ADObject $ADObject -Domain $Domain -ObjectType $ObjectType
            $CurrentTimestamp = [int64](New-TimeSpan -start (get-date "1/1/1970") -end (get-date)).TotalSeconds
            $MaxPasswordAge = [int](Get-ADDefaultDomainPasswordPolicy -Server $Server).MaxPasswordAge.Days
            $DaysLeft = [int]$MaxPasswordAge-([math]::Round(((($CurrentTimestamp-$TimestampPasswordLastSet)/24)/60)/60))
            if($DaysLeft -gt 0 -and -not $ForceUpdate) {
                $Message = "[+] $(Get-DateTime): $($DaysLeft) days remaining for the $ObjectType '$Domain\$SamAccountName'"
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                continue
            }

            $Message = "[+] $(Get-DateTime): Generating a new password for the $ObjectType '$Domain\$SamAccountName'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            $NewPassword = (Get-RandomCharacters -length $PassLength -characters $PassCharset)
            $Message = "[+] $(Get-DateTime): Updating the password of the $ObjectType '$Domain\$SamAccountName'"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            $ExitCode = Set-ADPassword -SamAccountName $SamAccountName -CurrentPassword $CurrentPassword -NewPassword $NewPassword -Server $Server -Domain $Domain -ObjectType $ObjectType
            if ($ExitCode -eq 0) {
                $Message = "[+] $(Get-DateTime): '$Domain\$SamAccountName's password Updated Successfully."
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                $UserRowIndex = [array]::IndexOf($CSVo.SamAccountName, $SamAccountName)
                $CSVo[$UserRowIndex].Password = $NewPassword
                $Return = Update-CSV -CSVo $CSVo -CSVFile $CSVFile -CSVDelimiter $CSVDelimiter
                if ($Return) {
                    $Message = "[+] $(Get-DateTime): '$CSVFile' CSV file Updated Successfully."
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                } else {
                    $Message = "[!] $(Get-DateTime): Failed to update the '$CSVFile' CSV file !"
                    Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                }
            } else {
                $Message = "[!] $(Get-DateTime): Failed to update the '$Domain\$SamAccountName's password !`r`n"
                $Message += $Stderr
                Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            }
        }
      } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

function UpdateHoneyUsersOrComputersPwd
{
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory=$true,
                   HelpMessage="Specify the input CSV file for updating users/services or computers(require 'Reset Password' permission) objects password.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFile,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the CSV delimiter (Default=',').")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVDelimiter = ',',

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the domain controller to use (Default => The default primary domain controller).")]
        [ValidateNotNullOrEmpty()]
        [string]$Server = $defaultPDC,

        [Parameter(Mandatory=$true,
                   HelpMessage="Specify the Active Directory object type (user or computer).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("user","computer")]
        [string]$ObjectType,

        [Parameter(Mandatory=$true,
                   HelpMessage="Specify the maximum number of characters for the password.")]
        [ValidateNotNullOrEmpty()]
        [int]$PassLength,

        [Parameter(Mandatory=$true,
                   HelpMessage="Specify how long the resource sleeps until the next check run.")]
        [ValidateNotNullOrEmpty()]
        [Double]$Delay,

        [Parameter(Mandatory=$false,
                   HelpMessage="Whether to force updating users/services or computers(require 'Reset Password' permission) objects password (Default=False).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($false,$true)]
        [bool]$ForceUpdate = $false,

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

    Process {
        Try {
            $CSVo = Import-Csv -Path $CSVFile -Delimiter $CSVDelimiter

            foreach ($data in $CSVo) { 
                $SamAccountName = $data.samAccountName
                $CurrentPassword =  $data.password
                $UserPrincipalName = $data.userPrincipalName
                $Domain = ($UserPrincipalName.split('@'))[1]

                if ($ObjectType -like "user") {
                    #####Checking if the domain user account exists or not#####
                    $ADUserObject = Get-ADUserOrComputerObject -SamAccountName $SamAccountName -Server $Server -Domain $Domain -ObjectType "user"
                    Gen-NewPassword -CSVo $CSVo -CSVFile $CSVFile -ADObject $ADUserObject -CurrentPassword $CurrentPassword -Server $Server -Domain $Domain -ObjectType "user" -CSVDelimiter $CSVDelimiter -ForceUpdate $ForceUpdate
                } elseif ($ObjectType -like "computer") {
                    #####Checking if the domain computer account exists or not#####
                    $ADComputerObject = Get-ADUserOrComputerObject -SamAccountName $SamAccountName -Server $Server -Domain $Domain -ObjectType "computer"
                    Gen-NewPassword -CSVo $CSVo -CSVFile $CSVFile -ADObject $ADComputerObject -CurrentPassword $CurrentPassword -Server $Server -Domain $Domain -ObjectType "computer" -CSVDelimiter $CSVDelimiter -ForceUpdate $ForceUpdate
                }
                Start-Sleep -s $Delay
            }

        } Catch {
            $Message = "[!] $(Get-DateTime): $_.Exception.Message"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    }
    End {}
}

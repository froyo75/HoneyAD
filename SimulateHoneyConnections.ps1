<#
.SYNOPSIS
    Simulate successful or bad network logon attempts using the HoneyUsers or HoneyComputers
.DESCRIPTION
    Imports a CSV file which contains the HoneyUser or HoneyComputers accounts then pickup randomly a HoneyUser or a HoneyComputer to simulate successful or failed login attempts.
    For a specific domain user/computer account, it mounts the "SYSVOL" Active Directory share. If the login attempt is successful, an event log id "4624" 
    with "logon type 3" (Network: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624) is raised 
    which updates the "LastLogon" and "LastLogonTimestamp" attributes, otherwise, bad login attempts result in updating the "badPwdCount" and "badPasswordTime" attributes.
.NOTES
    Version:        1.7
    Author:         @froyo75
    Creation Date:  07/09/2020
    Purpose/Change: 
        - 1.0 Initial script development
        - 1.1 Logging improvements
        - 1.2 Add Computer objects support + Some major fixes and improvements
        - 1.3 Add CSV delimiter option
        - 1.4 Add/Fix 'Domain/Server' support
        - 1.5 Fix 'CurrentLockoutThreshold' issue
        - 1.6 Fix login issue with domain users
        - 1.7 Checks if the 'badPwdCount' attribute exists before simulating bad login attempts
.EXAMPLE
    C:\PS> SimulateHoneyConnections -CSVFile C:\Users\Administrator\Desktop\UsersServices.csv -ObjectType user
    C:\PS> SimulateHoneyConnections -CSVFile C:\Users\Administrator\Desktop\UsersServices.csv -ObjectType user -MaxBadPwdCount 2
    C:\PS> SimulateHoneyConnections -CSVFile C:\Users\Administrator\Desktop\RS\Computers.csv -ObjectType computer -MaxBadPwdCount 2
#>

$BadPassword = "B@dP@ssw0rd"

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

function Get-RandomSamAccountName([array]$CSVo) {
    return Get-Random -InputObject $CSVo
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

function Access-SMBShare([string]$SamAccountName, [string]$Password, [string]$Server, [string]$Domain, [string]$FolderName, [string]$ObjectType) {
    Try {
        $DomainAccount = "$Domain\$SamAccountName"
        $SecureStringPassword = (ConvertTo-SecureString -AsPlainText -Force $Password)
        $CredentialObject = New-Object System.Management.Automation.PSCredential($DomainAccount,$SecureStringPassword)
        $NewLocation = $Domain.Replace('.','-')
        $Message = "[+] $(Get-DateTime): Creating a temporary drive '$NewLocation' that are mapped to '\\$Server\$FolderName' as the domain $ObjectType '$Domain\$SamAccountName'"
        Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        New-PSDrive -Name $NewLocation -PSProvider FileSystem -Scope Global -Root "\\$Server\$FolderName" -Credential $CredentialObject -ErrorAction Stop | Out-Null
        if(Test-path $NewLocation`:) { $ExitCode = 0 } else { $ExitCode = 1 }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } Finally {
        Get-PSDrive | ForEach {
            if ($_.Name -eq "$NewLocation" -and $_.Root -eq "\\$Server\$FolderName") {
                $Message = "[-] $(Get-DateTime): Removing the temporary drive '$NewLocation' that are mapped to '\\$Server\$FolderName'"
                Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                Remove-PSDrive -Name $NewLocation
            }
        }        
    } 
    return $ExitCode   
}

function SimulateHoneyConnections
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
                   HelpMessage="Specify the input CSV file.")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVFile,

        [Parameter(Mandatory=$false,
                HelpMessage="Specify the CSV delimiter (Default=',').")]
        [ValidateNotNullOrEmpty()]
        [string]$CSVDelimiter = ',',

        [Parameter(Mandatory=$true,
                   HelpMessage="Specify the Active Directory object type (user or computer).")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("user","computer")]
        [string]$ObjectType,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the maximum number of bad password attempts (Default=2).")]
        [ValidateNotNullOrEmpty()]
        [int]$MaxBadPwdCount=2,

        [Parameter(Mandatory=$false,
                   HelpMessage="Specify the SMB share to which the user/computer will connect for simulating successful or bad network logon attempts (Default=SYSVOL).")]
        [ValidateNotNullOrEmpty()]
        [string]$SMBFolderName = "SYSVOL",

        [Parameter(Mandatory=$false,
                HelpMessage="Specify the domain controller to use (Default => The default primary domain controller).")]
        [ValidateNotNullOrEmpty()]
        [string]$Server = (Get-ADDomain).pdcEmulator,
        
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
            $CSVo = Import-Csv -Path $CSVFile -Delimiter $CSVDelimiter
            $CSVCount = ($CSVo | Measure-Object).Count
            
            #Pickup a domain user/computer for successful login attempts
            $Message = "[+] $(Get-DateTime): Pickup a domain $ObjectType for successful login attempts"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            $SuccessRandomSamAccountNameObject = (Get-RandomSamAccountName -CSVo $CSVo)
            
            # Pickup a domain user/computer for bad login attempts
            $Message = "[+] $(Get-DateTime): Pickup a domain $ObjectType for bad login attempts"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            $FailedRandomSamAccountNameObject = (Get-RandomSamAccountName -CSVo $CSVo)
    
            # Checking if the current "SamAccountName" for success login attempts is the same as the "SamAccountName" for bad login attempts 
            # If yes, we randomize again to avoid overlapping
            While (($SuccessRandomSamAccountNameObject.sAMAccountName -like $FailedRandomSamAccountNameObject.sAMAccountName -and $CSVCount -gt 1)) {
                $FailedRandomSamAccountNameObject = (Get-RandomSamAccountName -CSVo $CSVo)
            }

            #####Simulating successful login attempts#####
            $SuccessSamAccountName = $SuccessRandomSamAccountNameObject.sAMAccountName
            $SuccessDomain = ($SuccessRandomSamAccountNameObject.userPrincipalName.split('@'))[1]
            $SuccessPassword = $SuccessRandomSamAccountNameObject.password

            $Message = "[+] $(Get-DateTime): The domain $ObjectType '$SuccessDomain\$SuccessSamAccountName' will be used for simulating successful login attempts"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage

            $SuccessADObject = Get-ADUserOrComputerObject -Domain $SuccessDomain -Server $Server -SamAccountName $SuccessSamAccountName -ObjectType $ObjectType
            if ($SuccessADObject) {
                $Message = "[+] $(Get-DateTime): Simulating successful login attempts for the domain $ObjectType '$SuccessDomain\$SuccessSamAccountName'"
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                $ExitCode = Access-SMBShare -SamAccountName $SuccessSamAccountName -Password $SuccessPassword -Server $Server -Domain $SuccessDomain -FolderName $SMBFolderName -ObjectType $ObjectType
                if ($ExitCode -eq 0) {
                    $Message = "[+] $(Get-DateTime): Login successful with '$SuccessDomain\$SuccessSamAccountName's !"
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                } else {
                    $Message = "[!] $(Get-DateTime): Failed to connect  with the '$SuccessDomain\$SuccessSamAccountName's  domain $ObjectType !"
                    Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                }
            }
            
            #####Simulating bad login attempts#####
            $FailedSamAccountName = $FailedRandomSamAccountNameObject.sAMAccountName
            $FailedDomain = ($FailedRandomSamAccountNameObject.userPrincipalName.split('@'))[1]

            $Message = "[+] $(Get-DateTime): The domain $ObjectType '$FailedDomain\$FailedSamAccountName' will be used for simulating bad login attempts"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
            
            $FailedADObject = Get-ADUserOrComputerObject -Domain $FailedDomain -Server $Server -SamAccountName $FailedSamAccountName -ObjectType $ObjectType
            if ($FailedADObject) {
                $Message = "[+] $(Get-DateTime): Simulating $MaxBadPwdCount bad login attempt(s) for the domain $ObjectType '$FailedDomain\$FailedSamAccountName'"
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage

                $Message = "[+] $(Get-DateTime): Retrieving the current 'badPwdCount' of the domain $ObjectType '$FailedDomain\$FailedSamAccountName'"
                Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                $ExistBadPwdCountAttribute = [bool]($FailedADObject | get-member badPwdCount)
                if ($ExistBadPwdCountAttribute) {
                    $CurrentBadPwdCount = $FailedADObject.badPwdCount
                    $Message = "[+] $(Get-DateTime): Retrieving the current 'LockoutThreshold' domain policy"
                    Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    $CurrentLockoutThreshold = [int](Get-ADDefaultDomainPasswordPolicy -Server $Server).LockoutThreshold

                    if (((($CurrentBadPwdCount+1) -lt $CurrentLockoutThreshold) -and ($CurrentBadPwdCount -lt $MaxBadPwdCount)) -or ($CurrentLockoutThreshold -eq 0)) {
                        if($MaxBadPwdCount -ge $CurrentLockoutThreshold -and $CurrentLockoutThreshold -gt 0) {
                            $Message = "[*] The maximum number of bad password attempts defined ($MaxBadPwdCount) is greater than the current 'LockoutThreshold' domain policy ($CurrentLockoutThreshold) ! reducing at $([int]($CurrentLockoutThreshold-1)) bad login attempt(s) for the '$FailedDomain\$FailedSamAccountName's domain $ObjectType !"
                            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                            $MaxBadPwdCount = $CurrentLockoutThreshold-1
                        }
                        For ($c=1; $c -le $MaxBadPwdCount; $c++) {
                            $Message = "[+] $(Get-DateTime): Bad login attempt with the '$FailedDomain\$FailedSamAccountName's domain $ObjectType !"
                            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                            $ExitCode = Access-SMBShare -SamAccountName $FailedSamAccountName -Password $BadPassword  -Server $Server -Domain $FailedDomain -FolderName $SMBFolderName -ObjectType $ObjectType
                        }
                    } elseif (($CurrentBadPwdCount -eq $CurrentLockoutThreshold) -and ($CurrentLockoutThreshold -ne 0)) {  
                        $Message = "[!] $(Get-DateTime): The $ObjectType account '$FailedDomain\$FailedSamAccountName' has been locked because there were too many logon attempts or password change attempts !"
                        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    } else {
                        $Message = "[*] $(Get-DateTime): The maximum number of failed login attempts has been reached for the domain $ObjectType '$FailedDomain\$FailedSamAccountName'"
                        Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                    }
                } else {
                    $Message = "[!] $(Get-DateTime): Failed to retrieve 'badPwdCount' attribute for the domain $ObjectType '$FailedDomain\$FailedSamAccountName' ! aborting bad login attempts simulation..."
                    Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
                }
            }
        } Catch {
            $Message = "[!] $(Get-DateTime): $_.Exception.Message"
            Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    }
    end {}
}

<#
.SYNOPSIS
    Create scheduled tasks automatically for the Honeypot project
.DESCRIPTION
    Create scheduled tasks automatically for the Honeypot project
.NOTES
  Version:        1.2
  Author:         @froyo75
  Creation Date:  08/09/2020
  Purpose/Change: 
        - 1.0 Initial script development
        - 1.1 Logging improvements
        - 1.2 Fix scheduled task 'Action' parameter
#>

$LogFile = "$PSScriptRoot\$(($MyInvocation.Mycommand.Name).replace("ps1", "log"))"
$WriteToLog = $true
$DisplayMessage = $true

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

function Create-NewScheduledTask([string]$TaskName, [string]$Description, [string]$Action, [string]$TriggerArgs) {
    Try {
        $ScheduledTaskObject = (Get-ScheduledTask -TaskName $TaskName)
        if ($ScheduledTaskObject -ne $null) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            $Message = "[-] $(Get-DateTime): Removing the scheduled task '$TaskName\$Description'"
            Logging -Message $Message -Color "Magenta" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
        $NewScheduledTaskAction = New-ScheduledTaskAction -Execute 'Powershell.exe' `
        -Argument "-NoProfile -WindowStyle Hidden -command `"$Action`""
        $NewScheduledTaskTrigger = iex "New-ScheduledTaskTrigger $TriggerArgs"
        $Message = "[+] $(Get-DateTime): Creating a new scheduled task '$TaskName\$Description'"
        Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        $NewScheduledTaskObject = Register-ScheduledTask -Action $NewScheduledTaskAction -Trigger $NewScheduledTaskTrigger -TaskName $TaskName -Description $Description
        if ($NewScheduledTaskObject.State -eq "Ready") {
            $Message = "[+] $(Get-DateTime): Scheduled task '$TaskName' successfully created !"
            Logging -Message $Message -Color "green" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
        }
    } Catch {
        $Message = "[!] $(Get-DateTime): $_.Exception.Message"
        Logging -Message $Message -Color "red" -LogFile $Logfile -WriteToLog $WriteToLog -DisplayMessage $DisplayMessage
    } 
}

#Create a new scheduled task for updating HoneyUsersServices' password automatically
$TaskName = "Update HoneyUsersServices password"
$Description = "Update the HoneyUsersServices' password automatically "
$Action = ". C:\Users\Administrator\Desktop\RS\UpdateHoneyUsersOrComputersPwd.ps1;UpdateHoneyUsersOrComputersPwd -CSVFile C:\Users\Administrator\Desktop\RS\UsersServices.csv -ObjectType user -PassLength 40 -Delay 5"
$Trigger =  "-Daily -At 9am"
Create-NewScheduledTask -TaskName $TaskName -Description $Description -Action $Action -TriggerArgs $Trigger

#Create a new scheduled task for updating HoneyComputers' password automatically
$TaskName = "Update HoneyComputers password"
$Description = "Update the HoneyComputers' password automatically "
$Action = ". C:\Users\Administrator\Desktop\RS\UpdateHoneyUsersOrComputersPwd.ps1;UpdateHoneyUsersOrComputersPwd -CSVFile C:\Users\Administrator\Desktop\RS\Computers.csv -ObjectType computer -PassLength 40 -Delay 5"
$Trigger =  "-Daily -At 5am"
Create-NewScheduledTask -TaskName $TaskName -Description $Description -Action $Action -TriggerArgs $Trigger

#Create a new scheduled task for simulating successful or bad network logon attempts using the HoneyUsersServices
$TaskName = "Simulate HoneyUsersServices Connections"
$Description = "Simulate successful or bad network logon attempts using the HoneyUsersServices"
$Action = ". C:\Users\Administrator\Desktop\RS\SimulateHoneyConnections.ps1;SimulateHoneyConnections -CSVFile C:\Users\Administrator\Desktop\UsersServices.csv -ObjectType user -MaxBadPwdCount 2"
$Trigger =  "-Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 2)"
Create-NewScheduledTask -TaskName $TaskName -Description $Description -Action $Action -TriggerArgs $Trigger

#Create a new scheduled task for simulating successful or bad network logon attempts using the HoneyComputers
$TaskName = "Simulate HoneyComputers Connections"
$Description = "Simulate successful or bad network logon attempts using the HoneyComputers"
$Action = ". C:\Users\Administrator\Desktop\RS\SimulateHoneyConnections.ps1;SimulateHoneyConnections -CSVFile C:\Users\Administrator\Desktop\RS\Computers.csv -ObjectType computer -MaxBadPwdCount 2"
$Trigger =  "-Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 24)"
Create-NewScheduledTask -TaskName $TaskName -Description $Description -Action $Action -TriggerArgs $Trigger

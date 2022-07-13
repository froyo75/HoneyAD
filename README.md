# HoneyAD - Create a HoneyPot environment for Active Directory

<img src="imgs/honeypot_ad.jpg" width="600px">

## Overview

A bunch of PowerShell scripts for setting up a Honey Pot environment for Active Directory.

* SimulateHoneyConnections.ps1 : Simulate successful or bad network logon attempts using the HoneyUsers or HoneyComputers.
* UpdateHoneyUsersOrComputersPwd.ps1 : Update the HoneyUsers/Services or HoneyComputers' password automatically (Changing computer password object require "Reset Password" permission !).
* GenerateHoneyObjects.ps1 : Create/Update Or Clear the HoneyPot environment (HoneyUsers, HoneyServices, HoneyComputers and SPNS) to lure attackers.
* CreateHoneyScheduledTasks.ps1 : Create scheduled tasks automatically for the Honeypot project.
* MonitorHoneyObjects.ps1 : Monitor and Track Honeypot object changes.

## Prerequisites

* "SimulateHoneyConnections.ps1" requires a limited domain user account.
* "UpdateHoneyUsersOrComputersPwd.ps1" requires a limited domain user account (Changing computer password object require "Reset Password" permission !).
* "GenerateHoneyObjects.ps1" requires at least a Domain Admin user account, or equivalent.
* "MonitorHoneyObjects.ps1" requires a limited domain user account.

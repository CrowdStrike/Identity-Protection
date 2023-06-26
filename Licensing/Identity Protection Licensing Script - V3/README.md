![CrowdStrike FalconIDP](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)

[![Twitter URL](https://img.shields.io/twitter/url?label=Follow%20%40CrowdStrike&style=social&url=https%3A%2F%2Ftwitter.com%2FCrowdStrike)](https://twitter.com/CrowdStrike)<br/>

# Identity Protection Licensing Script


+ [Overview](#overview)
+ [Prerequisites](#prerequisites)
+ [Running the Script](#running-the-script)
+ [Troubleshooting](#troubleshooting)

## Overview
This PowerShell script was developed to obtain all relevant domain information required to license Falcon Identity Protection.

## Prerequisites
Host Requirements:

* Domain-Joined, Server OS (Windows Server 2012 or later - does not have to be a domain controller). 
* Server OS in Workgroup OR Windows 10/11 - Supported but ONLY for accurately counting AzureAD users. The script will estimate the number of on-prem AD users based on the number of hybrid accounts synchronised via AzureAD connect but for an accurate number and entity counts, a domain-joined, server OS must be used.


User Permissions:
* AzureAD: Account with permission to obtain scopes "User.Read.All" and "AuditLog.Read.All"
* Active Directory: Domain User Account
* Running the script as administrator: ONLY required if you are running on a member server and ActiveDirectory tools are not installed OR from a domain controller. The script will handle these scenarios and inform you.  

Guidance:
* If you will be adding your Azure tenant to Falcon Identity, this script will prompt for your Azure credentials and count both native and hybrid accounts. If you run the script from a AD domain-joined machine and obtains on-prem AD users too, the script ensures that hybrid users are not counted twice and adjusts the final total by removing duplicates. 
* If you have a single forest, with a single domain, you run it once.
* If you have a single forest, with multiple domains, you can run it once and the entire forest will be covered.
* If you have multiple forests, you should run the script once per-forest and add the totals. 

## Running the Script
* Download a copy of the latest script in this directory script.
  * Save the script and run interactively from a PowerShell Window. 
  * You may need to change the PS execution policy, using the command:
  
  `set-executionpolicy unrestricted`

* Alternatively, copy and paste the script contents into a Powershell window. However, please ensure that the script is copied into one line, otherwise the script will not run. 

## Troubleshooting
A file called `cs_script_output.txt` will be created when you run the script, so if you have any issues you can obtain that file and send to your Crowdstrike representative for support. 

The script will automatically install the required Powershell modules (Microsoft Graph & ActiveDirectory) if not already installed on the machine.

For this, the machine will require internet access to Microsoft's powershell repository. If this connection is not possible, the script will stop and error accordingly in the `cs_script_output.txt` file.


<p align="center"><img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-footer.png"><BR/><img width="250px" src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/adversary-red-eyes.png"></P>
<h3><P align="center">WE STOP BREACHES</P></h3>

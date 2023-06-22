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
Operating System Requirements:
* Recommended - Server OS (Windows Server 2012 or later)
* Windows 10 - Supported but ONLY for counting AzureAD users. For Active Directory and entity counts, a server OS must be used.

Domain Requirements:
* To collect information from AD, the machine MUST be domain joined. 
* The script will run on a non-domain joined (workgroup) machine however it will ONLY count users from AzureAD (so appropriate if the customer doesnt have on-prem AD). 

User Permissions:
* AzureAD: Account with permission to obtain scopes "User.Read.All" and "AuditLog.Read.All"
* Active Directory: Domain User Account
* Local Admin is ONLY required if you are running on a member server and ActiveDirectory tools are not installed (script will handle this error case and inform you). 

Guidance:
* If you will be adding in your Azure tenant to Falcon Identity, this script will prompt for your Azure credentials and obtain the total count for active accounts that live in Azure only (not domain synchronized)
* If you havea single forest, with a single domain, you run it once.
* If you havea single forest, with multiple domains, you can run it once and the entire forest will be covered.
* If you have multiple forests, you should run the script once per-forest. 

## Running the Script
* Download a copy of the latest PowerShell .ps1 script.
* Save the script and run interactively from a PowerShell Window. 
* You may need to change the PS execution policy, using the command:

`set-executionpolicy unrestricted`

## Troubleshooting
A file called `cs_script_output.txt` will be created when you run the script, so if you have any issues you can obtain that file and send to your Crowdstrike representative for support. 

The script will automatically install the required Powershell modules (Microsoft Graph & ActiveDirectory) if not already installed on the machine.

For this, the machine will require internet access to Microsoft's powershell repository. If this connection is not possible, the script will stop and error accordingly in the `cs_script_output.txt` file.


<p align="center"><img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-footer.png"><BR/><img width="250px" src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/adversary-red-eyes.png"></P>
<h3><P align="center">WE STOP BREACHES</P></h3>
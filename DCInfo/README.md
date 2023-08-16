![CrowdStrike FalconIDP](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png)

[![Twitter URL](https://img.shields.io/twitter/url?label=Follow%20%40CrowdStrike&style=social&url=https%3A%2F%2Ftwitter.com%2FCrowdStrike)](https://twitter.com/CrowdStrike)<br/>

# Identity Protection Domain Controller Info Script


+ [Overview](#overview)
+ [Prerequisites](#prerequisites)
+ [Running the Script](#running-the-script)

## Overview
This PowerShell script was developed to obtain all relevant domain controller information. This can be helpful when deploying Falcon Identity Protection.

## Prerequisites
Operating System Requirements:
* Server OS (Windows Server 2012 or later)

Domain Requirements:
* To collect information from AD, the machine MUST be domain joined. 

User Permissions:
* Local Admin only (to install Powershell modules). 

* If you have a single forest, with a single domain, you run it once.
* If you have a single forest, with multiple domains, you can run it once per domain.
* If you have multiple forests, you should run the script once per domain in each forest, as described above.

## Running the Script
1. Login to the Falcon Console and navigate to Configuration → Response Scripts & Files → Scipts and select "Create Script". 
2. Give the Script a Name (in this example DCInfo) and a Description and paste this script found [here](./CS-DCInfo.ps1).
3. Under Permissions tick "RTR Active Responder and Administrator" and click "Save".
4. Navigate to the machine from where you will run PSFalcon. This can be any machine you use that has connectivity to the Falcon Cloud. No connection to the domain or other DCs is necessary. Follow steps 1 and 2 under [Multiple Hosts](#multiple-hosts) in this article to install the PS Module and generate an OAuth token for the API. 
5. Create a Host Group in Falcon containing all the domain controllers. To find the group ID, edit the group in the Falcon console and the ID is listed in the address bar at the end of the URL. Looks like: 
    * falcon.crowdstrike.com/hosts/groups-new/edit/***61592f432fd9447cb5bc2f9d0dd8dbe4***

6. Copy this Powershell Script to the machine and execute it in the Powershell window you used in Step 4. 
    ```powershell
    $groupid = "INSERT GROUP ID" ##Insert Group ID
    $timeout = "600" ##Insert Preferred Timeout
    
    $runscript = Invoke-FalconRtr -Command runscript -CloudFile='DCInfo' -GroupId $groupid -Timeout $timeout
    $collectinfo = Invoke-FalconRtr -Command cat cs-idp-dcinfo.csv -GroupId $groupid -Timeout $timeout | Select-Object -ExpandProperty stdout | convertfrom-csv
    $collectinfo | where {$_."GlobalCatalog" -notcontains "GlobalCatalog"} | Export-Csv -NoTypeInformation cs-idp-dcinfo-all.csv
    ```
7. This will create a CSV file called "idp-info-all.csv" like the example [here](./cs-idp-dcinfo-all.csv).

## Multiple Hosts
Running this on multiple hosts requires use of one of the Falcon SDKs. It is not possible from the Falcon Console to issue a RTR to multiple hosts. 

We will use [PSFalcon](https://github.com/CrowdStrike/psfalcon) in this example however an alternative like FalconPy could also be used. All other SDKs are available here: https://github.com/CrowdStrike.

### Prerequisites:

* Create a host group for all the DC's they wish to target. To find the group ID, edit the group in the Falcon console and the ID is listed in the address bar at the end of the URL. Looks like: 
https://falcon.crowdstrike.com/hosts/groups-new/edit/12345f678fd9012cb3bc2f4d5dd6dbe7
* Nominate a machine from where you will run the Powershell script. This doesnt have any special requirements, other than an admin account to install the PS module and accessibility to the Falcon API.

![Falcon-Console-API-Token-Settings](https://github.com/CrowdStrike/Identity-Protection/assets/94929838/e9ba9c58-ce14-449e-a407-325d32c09e19)

### Steps
1. Run Powershell as Administrator & Install the PS Falcon Module on the machine nominated to run the script:
   ```powershell
   Install-Module PSFalcon
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
   Import-Module PSFalcon
   ```

2. Authenticate with API Key by running:
   ```powershell
   Request-FalconToken
   ```
   Enter API ClientID and Secret when prompted. 

### Notes

Disk Information (Drive Letters, Free and Used) is outputted as an array when the machine has more than one disk. In this scenario, the information is added under a single cell per row, however the values for each drive are separated with a new line. So expand the cell in excel and it is easy to read.

<p align="center"><img src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo-footer.png"><BR/><img width="250px" src="https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/adversary-red-eyes.png"></P>
<h3><P align="center">WE STOP BREACHES</P></h3>

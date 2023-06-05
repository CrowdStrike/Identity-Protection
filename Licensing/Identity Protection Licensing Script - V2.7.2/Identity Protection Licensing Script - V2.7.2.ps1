### Copyright (c) 2022 CrowdStrike, Inc.
### Permission is hereby granted, free of charge, to any person obtaining a copy
### of this software and associated documentation files (the "Software"), to deal
### in the Software without restriction, including without limitation the rights
### to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
### copies of the Software, and to permit persons to whom the Software is
### furnished to do so, subject to the following conditions:
### The above copyright notice and this permission notice shall be included in all
### copies or substantial portions of the Software.
### THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
### IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
### FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
### AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
### LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
### OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
### SOFTWARE.


    #### v2.7.2 - 14th September 2022

    Write-Host "`n#### Prerequisite Check #### " -ForegroundColor Blue
    
    #### Check Running Powershell Running as Administrator ####
    $scriptversion = 'v2.7.2'
    write-host "- Script Version is $scriptversion..." -ForegroundColor Yellow

    write-host "- Checking Script is running as administrator..." -ForegroundColor Yellow
    
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isadmin -eq $false) {
        throw 'Script not running as administrator. Run Powershell as an administrator, then re-run the script.' 
    }
    else {
        write-host "- Script is running as administrator..." -ForegroundColor Green
    }

    #### Check Powershell Version ####

    write-host "- Checking Powershell Version..." -ForegroundColor Yellow
    
    $PSversion = $PSVersionTable.PSVersion.Major
    write-host "- Powershell version is `"$PSversion`"..." -ForegroundColor Yellow

    if ($PSversion -lt '5') {
        throw "- Powershell version is $PSVersion which is not supported. Please run the script on a machine running Powershell 5."
    }
    elseif ($PSversion -eq '7') {
        write-host "- Powershell version is $PSVersion, switching to Version 5. Please re-run the script at the next prompt...`n`n" -ForegroundColor Red 
        powershell -Version 5
        exit
    }
    else {}

    ### Get OS Info ###
    
    $global:osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $global:osName = (Get-CimInstance -ClassName Win32_OperatingSystem).name

    if ($osInfo.ProductType -eq 1) {
        $capability = "AzureADOnly"
        write-host "`n- !!### WARNING ###!!`n`nThis is a client operating system which means the script can only count active AzureAD users. To count users from Active Directory or to obtain sizing information, please re-run the script on a domain-joined, server operating system.`n`nPress any key to continue...or CTRL+C to exit" -ForegroundColor Yellow
        $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') | out-null
    }
    elseif ([string]::IsNullOrEmpty($env:USERDNSDomain)) {
        $capability = "AzureADOnly"
        write-host "`n- !!### WARNING ###!!`n`nThis machine is not domain joined which means the script can only count active AzureAD users. To count users from Active Directory or to obtain sizing information, please re-run the script on a domain-joined, server operating system.`n`nPress any key to continue...or CTRL+C to exit" -ForegroundColor Yellow 
        $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') | out-null
    }
    else {
        $capability = "any"
        write-host "`n- Prerequisites check complete...`n`n" -ForegroundColor Green
    }
    
    
    #### Get Script Location ####
    $BundleLocation = $PSScriptRoot
    
    #### Log Output ####
    # Stop if running
    $ErrorActionPreference="SilentlyContinue"
    Stop-Transcript | out-null
    
    # Start
    $ErrorActionPreference = "Continue"
    Start-Transcript -path "$BundleLocation\cs_script_output.txt" | out-null
    $output = "$BundleLocation\cs_script_output.txt"
    
    ##### FUNCTIONS ######
    
        ### Create Data Tables ###
    
        function createActiveUsersTable {
    
            ### If Table Exists, Delete ###
    
            if ([string]::IsNullOrEmpty($ActiveUsersTable)) {
            }
    
            else {
                Write-host "Table Exists for Active Users from previous run...Clearing Data..." -ForegroundColor Yellow
                $ActiveUsersTable.Clear()
            }
    
            ### Create Table ###
    
            $global:ActiveUsersTable = New-Object system.Data.DataTable 'APIOutput'
            $newcol = New-Object system.Data.DataColumn 'Domain',([string]); $ActiveUsersTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'DC',([string]); $ActiveUsersTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'Successful Connection?',([string]); $ActiveUsersTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'IDP Licensing: Active Users',([string]); $ActiveUsersTable.columns.add($newcol)
        }

        function createEntityCountTable {
    
            ### If Table Exists, Delete ###
    
            if ([string]::IsNullOrEmpty($EntityCountTable)) {
            }
    
            else {
                Write-host "Table Exists for Entity Count from previous run...Clearing Data..." -ForegroundColor Yellow
                $EntityCountTable.Clear()
            }
    
            ### Create Table ###
    
            $global:EntityCountTable = New-Object system.Data.DataTable 'APIOutput'
            $newcol = New-Object system.Data.DataColumn 'Domain',([string]); $EntityCountTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'DC',([string]); $EntityCountTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'Successful Connection?',([string]); $EntityCountTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'DC Count',([string]); $EntityCountTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'Total Entity Count',([string]); $EntityCountTable.columns.add($newcol)

            
    
        }
    
        ### Find Active Azure AD Users ###
    
        function get-Azure {
    
            ### Disable IE Enahnced Security (Temporary) as on servers where IE is the only browser installed, this prevents the AzureAD login screen loading ###
    
            Write-Host "`n#### IE Enhanced Security Check #### " -ForegroundColor Blue
    
    
            function get-InternetExplorerESC-Admin {
                $global:AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
                $global:ie_admin_status = Get-ItemProperty -Path $AdminKey -Name "IsInstalled"
            }
    
            function Disable-InternetExplorerESC-Admin {
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
            Rundll32 iesetup.dll, IEHardenLMSettings
            Rundll32 iesetup.dll, IEHardenAdmin
            Write-Host "`n- IE Enhanced Security Configuration (ESC) has been temporarily disabled for Administrators." -ForegroundColor Yellow
            }
    
            function Enable-InternetExplorerESC-Admin {
            Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 1 -Force
            Rundll32 iesetup.dll, IEHardenLMSettings
            Rundll32 iesetup.dll, IEHardenAdmin
            Write-Host "`n- IE Enhanced Security Configuration (ESC) has been re-enabled for Users." -ForegroundColor Green
            }
    
            if ($osInfo.ProductType -eq 1) {
                Write-Host "`n- ClientOS - Skipping IE Enhanced Security Configuration (ESC) check." -ForegroundColor Yellow
            }
            else{
                get-InternetExplorerESC-Admin
                if ($ie_admin_status.IsInstalled -eq 1) {
                    Disable-InternetExplorerESC-Admin
                }
                else {
                    Write-Host "`n- No changes to IE Enhanced Security Configuration (ESC) required." -ForegroundColor Yellow
                }
            }
    
            #### TLS Version Check ####
    
            Write-Host "`n#### Checking TLS Version #### " -ForegroundColor Blue
    
            $tlsversion = [Net.ServicePointManager]::SecurityProtocol
    
            if ($tlsversion -ne 'Tls12') {
                Write-Host "`n- TLS version is $tlsversion. Setting TLS version to 1.2..." -ForegroundColor Yellow
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $tlsversion = [Net.ServicePointManager]::SecurityProtocol
                Write-Host "`n- TLS version is now $tlsversion." -ForegroundColor Yellow
            }
            else {
            Write-Host "`n- TLS version is $tlsversion." -ForegroundColor Yellow
            }
    

            #### Installing AzureAD Powershell Module ####

            Write-Host "`n#### Installing Powershell Module for AzureAD #### " -ForegroundColor Blue

            if (Get-Module -ListAvailable -Name AzureAD) {
                write-error "`n`n`n- The AzureAD module is already installed on this system. `"AzureADPreview`" is required to count active users in AzureAD and both cannot be installed at the same time. Please follow the steps below and re-run the script:`n`n-- Close this Powershell Window and open a new window (runnung as administrator)`n`n`n-- Run `"Uninstall-Module -Name AzureAD`"`n`n`n- If removing the AzureAD module is not possible, please run the script on another system.`n`n`n" -ErrorAction stop
            }
            else {}

            if (Get-Module -ListAvailable -Name AzureADPreview) {
                
                try {
                $error.clear()
                Write-Host "- AzureAD Powershell Module is already installed...importing..." -ForegroundColor Green
                Import-Module AzureADPreview
                }
                catch {
                        $lasterror = $error[0].Exception | Select-Object Message
                        Throw "Unable to Import Powershell Module final. Review errors above or in the $output file."
                }
            }
            else {
                try {
                        $error.clear()
                        Write-Host "- Downloading & Installing AzureAD Powershell Module..." -ForegroundColor Yellow
                        Install-Module AzureADPreview -Allowclobber -Force -ErrorAction stop -Verbose
                        Write-host "- Importing AzureAD Powershell Module..." -ForegroundColor Yellow
                        Import-Module AzureADPreview -ErrorAction stop
                    }
                    catch {
                        $lasterror = $error[0].Exception | Select-Object Message
                        throw "- Unable to install the AzureAD powershell module. Review errors above or in the $output file."
                    }
            }

            ##### Connect to AzureAD #####

            Write-Host "`n#### AzureAD Connectivity ####" -ForegroundColor Blue

            try {
                $error.clear()
                $testconnection = Get-AzureADTenantDetail -ErrorAction stop | out-null
            }
            catch {
                $lasterror = $error[0].Exception | Select-Object Message
                if ($lasterror -match "You must call the Connect-AzureAD cmdlet before calling any other cmdlets.") {
            
                    Write-Host "- Not connected to AzureAD..." -ForegroundColor Yellow
                    try {
                                write-host "- Authenticating to AzureAD..." -ForegroundColor Yellow
                                Import-Module AzureADPreview -ErrorAction stop
                                Connect-AzureAD -ErrorAction stop | out-null
                            }
                            catch {
                                throw "- Authenticating to AzureAD failed. Review errors above or in the $output file."
                    }
                }
                elseif ($lasterror -match "The term 'Get-AzureADTenantDetail' is not recognized as a name of a cmdlet, function, script file, or executable program.") {

                    throw "Unable to import the AzureAD Powershell module, please try doing this manually 'import-module AzureAD' and re-run the script. If the problem persists, please contact support."
                }
                else {
                    throw "Authenticating to AzureAD failed. Review errors above or in the $output file."
                }
            }

            Write-Host "- Connected to AzureAD..." -ForegroundColor Yellow

            ##### Count Active AzureAD Users #####

            Write-Host "`n#### Obtain Active AzureAD Users ####" -ForegroundColor Blue

    
            ##### Get AzureAD GUID #####
            $AzureDomainName = (Get-AzureADTenantDetail).VerifiedDomains| Where-Object {$_.'_Default' -eq "True"} | select -ExpandProperty Name
    
            Write-Host "- Counting Active Users..." -ForegroundColor Yellow
    
            ### If Table Exists, Delete ###
    
            if ([string]::IsNullOrEmpty($AzureADUsersTable)) {
            }
    
            else {
                $AzureADUsersTable.Clear()
            }
    
            ### Create Table for AzureAD Users ###
    
            $global:AzureADUsersTable = New-Object system.Data.DataTable 'AzureADUsersTable'
            $newcol = New-Object system.Data.DataColumn 'User',([string]); $AzureADUsersTable.columns.add($newcol)
            $newcol = New-Object system.Data.DataColumn 'Last Login Time',([string]); $AzureADUsersTable.columns.add($newcol)
    
            $users = get-azureaduser -all:$true | where-object {$_.AccountEnabled -eq 'True' -AND $_.ImmutableID -eq $null -AND $_.UserType -eq 'Member'} | select UserPrincipalName
            $usercount = $users.count

            write-host "- Discovered `"$usercount`" enabled, cloud-only, user accounts. Counting which accounts have been active in the last 90 days..." -ForegroundColor Yellow
            
            $global:waittime = "10"  ##seconds
            $DateStr = (Get-Date).AddDays(-90)
            $getpast90days = $DateStr.ToString("yyyy-MM-dd")
            $count=0
            

            foreach ($i in $users) {

                    $global:UPN = $i.UserPrincipalName
                    $LoginTime = $null
                    $error.Clear()
                    do {
                        $rateLimitExceeded = $false
                        $lasterror = $null
                        $LoginTime = try { Get-AzureAdAuditSigninLogs -top 1 -filter "userprincipalname eq '$UPN' AND createdDateTime gt $getpast90days" | select -expandproperty CreatedDateTime
                        }
                        catch {
                            $lasterror = $error[0].Exception | Select-Object Message
                            if ($lasterror -like "*Too Many Requests*" -OR $lasterror -like "*This request is throttled. Please try again after the value specified in the Retry-After header.*") {
                                $rateLimitExceeded = $true
                                write-host "Azure Rate Limit Reached...Waiting $waittime seconds before next attempt..." -ForegroundColor Yellow
                                Start-Sleep -Seconds $waittime
                            }
                            elseif ($lasterror -like "*Neither tenant is B2C or tenant doesn't have premium license*") {
                                throw "`nThe free version of AzureAD is not supported by Identity Protection. Skipping AzureAD user count..." 
                            }
                            else {
                            throw "`n- Unable to obtain active AzureAD Users.`n`nLast error is `"$lasterror`"`n`nReview errors above or in the $output file."
                            }
                        }
                    }
                    until ($rateLimitExceeded -eq $false)

    
                    if (-not[string]::IsNullOrEmpty($LoginTime)) {
                    $row = $AzureADUsersTable.NewRow()
                    $row.'User' = $i.UserPrincipalName
                    $row.'Last Login Time' = $LoginTime
                    $AzureADUsersTable.Rows.Add($row)
                    }
                    else {
                    $row = $AzureADUsersTable.NewRow()
                    $row.'User' = $i.UserPrincipalName
                    $row.'Last Login Time' = "Never Logged In"
                    $AzureADUsersTable.Rows.Add($row)
                    }

                    $count++
                    write-host "- Checked $count of a total `"$usercount`" enabled, cloud-only, user accounts..." -ForegroundColor Green
                
            }
            
            $global:activeAzureADusers = ($AzureADUsersTable | where-object {$_.'Last Login Time' -ne "Never Logged In"} | Measure-Object).count
    
    
            ### Update Table ###
            if ($activeAzureADusers -ne "0") {
            Write-host "`n- Active AzureAD Users Received. Updating Table..." -ForegroundColor Green
    
            $row = $ActiveUsersTable.NewRow()
            $row.'Domain' = $AzureDomainName
            $row.'DC'= "N/A - AzureAD"
            $row.'IDP Licensing: Active Users' = $activeAzureADusers

            $ActiveUsersTable.Rows.Add($row)

            }
            else {
                Write-host "`nUnable to obtain active AzureAD Users. Review errors above or in the $output file." -ForegroundColor Red
            }
    
            ### Re-enable Internet Explorer Enhanced Security ###
    
            if ($ie_admin_status.IsInstalled -eq 1) {
                Enable-InternetExplorerESC-Admin
            }
    
            else {
            }
    
        }
    
        ### Find Active AD Users ###
    
        function get-ADUsers {
    
            #### Check OS Version ####
    
            Write-Host "`n#### Active Directory Powershell Module Check #### " -ForegroundColor Blue
    
            if ($osInfo.ProductType -eq "2"){
                write-host "`n- Domain Controller - Checking for ActiveDirectory Powershell Module" -ForegroundColor Yellow
    
                ##### Check if AD Powershell Module is Installed #####
    
                if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Write-Host "`n- ActiveDirectory Powershell Module is already installed...`n" -ForegroundColor Green
                }
    
                else {
                    try {
                    Write-Host "`n- Downloading ActiveDirectory Powershell Module..." -ForegroundColor Yellow
                    Install-Module ActiveDirectory -Force -ErrorAction stop
                    Write-host "`n- Installing ActiveDirectory Powershell Module..." -ForegroundColor Yellow
                    }
                    catch {
                    throw "`n- Unable to install the ActiveDirectory powershell module. Review errors above or in the $output file."
                    }
                
                Write-host "`n- Successfully installed ActiveDirectory Powershell Module..." -ForegroundColor Green
                }
    
            }
            elseif ($osInfo.ProductType -eq "3"){
                write-host "`n- Member Server - Checking for ActiveDirectory Powershell Module" -ForegroundColor Yellow
    
                ##### Check if AD Powershell Module is Installed #####
    
                if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Write-Host "`n- RSAT Powershell Module is already installed...`n" -ForegroundColor Green
                }
    
                else {
                    try {
                    Write-host "`n- Installing RSAT Powershell Module..." -ForegroundColor Yellow
                    Install-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction stop | out-null
                    }
                    catch {
                    throw "`n- Unable to install the RSAT powershell module. Review errors above or in the $output file."
                    }
                
                Write-host "`n- Successfully installed RSAT Powershell Module..." -ForegroundColor Green
                }
    
            }
            else {
                throw "`n- Unsupported OS. Please run this script from Windows Server 2012 or later..."
            }
    
            Write-Host "`n#### Getting Active Directory Domains & Primary DC's #### " -ForegroundColor Blue
    
            ### Get Domain in Active Directory Forest ###
            try {
            $Domains = (Get-ADForest).Domains
            }
            catch {
                throw '- Unable to connect to Active Directory. Please make sure the machine is domain joined and you are logged on with a domain account. If you counted AzureAD users and only require that number for your use case, please type $ActiveUsersTable in the Powershell prompt.'
            }
    
            ### Get Domain Controller list ###
            $DCList = ForEach ($Domain in $Domains) {
                Get-ADDomainController -DomainName $Domain -Discover -Service PrimaryDC
            }
            
    
            Write-host "`n- Gathered Domains & DC's. Updating Table..." -ForegroundColor Green    
    
            ### Update Table with Domain & DC Info ###
            foreach ($i in $DCList) {
                $row = $ActiveUsersTable.NewRow()
                $row.'Domain' = $($i."Domain")
                $row.'DC'= $($i."Hostname")
                $ActiveUsersTable.Rows.Add($row)
                $row = $EntityCountTable.NewRow()
                $row.'Domain' = $($i."Domain")
                $row.'DC'= $($i."Hostname")
                $EntityCountTable.Rows.Add($row)
            }

            ### Test Connectivity to DC's ###
            foreach ($i in $DCList) {

                $DCconnection = $null
                $DC = $i."Hostname"
                $domain = $i.'Domain'
                Write-host "`n- Testing Connection to `"$DC`"..." -ForegroundColor yellow
                $DCconnection = Test-NetConnection $DC -Port 9389 | select -ExpandProperty TcpTestSucceeded
                if ($DCconnection -eq 'True') {
                    Write-host "`n- Connection Successful to `"$DC`"..." -ForegroundColor Green
                }
                else {
                    Write-host "`n- Skipping `"$domain`". Unable to connect to domain controller `"$DC`" on Active Directory Web Services Port (TCP 9389)." -ForegroundColor Red
                }
            $ActiveUsersTable | where {$_.DC -eq $DC} | foreach {$_.'Successful Connection?' = "$DCconnection"}
            $EntityCountTable | where {$_.DC -eq $DC} | foreach {$_.'Successful Connection?' = "$DCconnection"}
            }

            Write-Host "`n#### Active Directory Active Users #### " -ForegroundColor Blue

            ### Update Table with Active AD Users for Each Domain ###
    
            try {
    
                foreach ($row in $ActiveUsersTable | Where-Object {$_.'DC' -ne 'N/A - AzureAD'}) {
                    
                    $DC = $row.'DC'
                    $domain = $row.'Domain'
                    $DCconnection = $row.'Successful Connection?'

                    if ($DCconnection -eq 'True') {

                    $ActiveUsers = (Get-ADUser -server $DC -filter * -properties LastLogonDate,Enabled -ErrorAction continue | Where-Object {$_.lastlogondate -ge (get-date).adddays(-90) -and $_.enabled -eq "True"} | Measure-Object).count
                    
                    $ActiveUsersTable | where {$_.DC -eq $DC} | foreach {$_.'IDP Licensing: Active Users' = "$ActiveUsers"}

                    Write-host "`n- Active AD Users obtained for `"$domain`" - ($ActiveUsers). Updating Table..." -ForegroundColor Green

                    }
                    else {
                        Write-host "`n- Skipping `"$domain`". Unable to connect to domain controller `"$DC`" on Active Directory Web Services Port (TCP 9389)." -ForegroundColor Red
                        $ActiveUsersTable | where {$_.DC -eq $DC} | foreach {$_.'IDP Licensing: Active Users' = "N/A - Connect Error"}
                    }
    
                }
            }
            catch {
                Throw "`n- Unable to obtain Active AD Users. Review errors above or in the $output file."
            }
    

            ### Update Table with Entities for Each Domain ###

            Write-Host "`n#### Active Directory Total Entity (User) Count #### " -ForegroundColor Blue
    
            try {
    
                foreach ($row in $EntityCountTable | Where-Object {$_.'DC' -ne 'N/A - AzureAD'}) {

                    $DC = $row.'DC'
                    $domain = $row.'Domain'
                    $DCconnection = $row.'Successful Connection?'

                    if ($DCconnection -eq 'True') {
    
                    $UserCount = (Get-ADUser -server $DC -filter * | Measure-Object).count
                    $ComputerCount = (Get-ADComputer -server $DC -filter * | Measure-Object).count
                    $EntityCount = $UserCount + $ComputerCount
                    
                    $EntityCountTable | where {$_.DC -eq $DC} | foreach {$_.'Total Entity Count' = "$EntityCount"}
                    Write-host "`n- Entity Count (Total AD Users) obtained for `"$domain`" - ($EntityCount). Updating Table..." -ForegroundColor Green
                    }
                    else {
                        Write-host "`n- Skipping `"$domain`". Unable to connect to domain controller `"$DC`" on Active Directory Web Services Port (TCP 9389)." -ForegroundColor Red
                        $EntityCountTable | where {$_.DC -eq $DC} | foreach {$_.'Total Entity Count' = "N/A - Connect Error"}
                    }

                }
            }
            catch {
                Throw "`n- Unable to obtain Entity Count. Review errors above or in the $output file."
            }


            ### Update Table with DC Count for Each Domain ###

            Write-Host "`n#### Active Directory Domain Controller Count #### " -ForegroundColor Blue
    
            try {
    
                foreach ($row in $EntityCountTable | Where-Object {$_.'DC' -ne 'N/A - AzureAD'}) {
                    
                    $DC = $row.'DC'
                    $domain = $row.'Domain'
                    $DCconnection = $row.'Successful Connection?'

                    if ($DCconnection -eq 'True') {
                    $DCCount = (Get-ADDomainController -filter * -server $DC | Measure-Object).count
                    $EntityCountTable | where {$_.DC -eq $DC} | foreach {$_.'DC Count' = "$DCCount"}
                    Write-host "`n- Total DC count obtained for `"$domain`" - ($DCCount). Updating Table..." -ForegroundColor Green
                    }
                    else {
                        Write-host "`n- Skipping `"$domain`". Unable to connect to domain controller `"$DC`" on Active Directory Web Services Port (TCP 9389)." -ForegroundColor Red
                        $EntityCountTable | where {$_.DC -eq $DC} | foreach {$_.'DC Count' = "N/A - Connect Error"}
                    }
                }
            }
            catch {
                Throw "`n- Unable to obtain Domain Controller Count. Review errors above or in the $output file."
            }
        }


        ### Calculate Total Active Users ###
    
        function get-totalUsers {
    
        $totalActiveUsers = ($ActiveUsersTable | where-object {$_.'IDP Licensing: Active Users' -ne "N/A - Connect Error"}  | Measure-Object 'IDP Licensing: Active Users' -Sum).Sum
    
        $row = $ActiveUsersTable.NewRow()
        $row.'Domain' = "FOREST TOTALS"
        $row.'IDP Licensing: Active Users' = $totalActiveUsers
        $ActiveUsersTable.Rows.Add($row)
    
        }

        function get-totalEntities {
    
        $totalDCs = ($EntityCountTable | where-object {$_.'DC Count' -ne "N/A - Connect Error"} | Measure-Object 'DC Count' -Sum).Sum
        $totalEntities = ($EntityCountTable | where-object {$_.'Total Entity Count' -ne "N/A - Connect Error"} | Measure-Object 'Total Entity Count' -Sum).Sum
    
        $row = $EntityCountTable.NewRow()
        $row.'Domain' = "FOREST TOTALS"
        $row.'DC Count' = $totalDCs
        $row.'Total Entity Count' = $totalEntities
        $EntityCountTable.Rows.Add($row)

        $global:finalEntityCountTable = $EntityCountTable | select Domain,'Successful Connection?', 'DC Count','Total Entity Count'
    
        }



    
    
### Create Output Tables ###
createActiveUsersTable
createEntityCountTable
    
if ($capability -eq 'AzureADOnly') {
    get-Azure
    get-totalUsers
    Write-Host "`n#### IDENTITY PROTECTION LICENSING QUOTE: TOTAL ACTIVE USERS ####`nThis information should be provided to Crowdstrike in order to provide an indicative cost of the solution. " -ForegroundColor GREEN
    $ActiveUsersTable | format-table
}
else {

    # Check if Azure AD in scope and if so query for the number of Azure AD users
    $title    = ''
    $question = "`nWould you like to check Azure AD for accounts?"
    $choices  = '&Yes', '&No'
    
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)

    if ($decision -eq 0) {
        get-Azure
        get-ADUsers
        get-totalUsers
        get-totalEntities
        Write-Host "`n#### IDENTITY PROTECTION LICENSING QUOTE: TOTAL ACTIVE USERS ####`nThis information should be provided to Crowdstrike in order to provide an indicative cost of the solution. " -ForegroundColor GREEN
        $ActiveUsersTable | format-table
        Write-Host "`n#### IDENTITY PROTECTION PROVISIONING: DC & Entity Counts ####`nThis information should be provided to Crowdstrike in order to provision the Identity Protection module on your CID. " -ForegroundColor GREEN
        $finalEntityCountTable | format-table
    } else {
        get-ADUsers
        get-totalUsers
        get-totalEntities
        Write-Host "`n#### IDENTITY PROTECTION LICENSING QUOTE: TOTAL ACTIVE USERS #### " -ForegroundColor GREEN
        $ActiveUsersTable | format-table
        Write-Host "`n#### Identity Protection Provisioning: DC & Entity Counts #### " -ForegroundColor GREEN
        $finalEntityCountTable | format-table
    }

}
Stop-Transcript | out-null

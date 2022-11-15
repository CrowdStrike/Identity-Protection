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

    #### v1.1 - 15th November 2022


    $hostname = [System.Net.Dns]::GetHostByName($env:computerName) | Select-Object -ExpandProperty HostName
    $volume = Get-PSDrive | Where-Object {($_.Used -NE $null -and $_.Used -NE '0')} | Select-Object Name,Used,Free
    $volume_used = $volume | Select-Object @{Name="Used"; Expression={[math]::round($_.Used/1GB, 2) }}
    $volume_free = $volume | Select-Object @{Name="Free"; Expression={[math]::round($_.Free/1GB, 2) }}
     
    $adinfo = get-addomaincontroller -server $hostname | select-object Hostname,isglobalcatalog,Site,Forest,OperationMasterRoles
     
    $table = New-Object system.Data.DataTable 'DCInfoTable'
    $newcol = New-Object system.Data.DataColumn Hostname,([string]); $table.columns.add($newcol)
    $newcol = New-Object system.Data.DataColumn GlobalCatalog,([Boolean]); $table.columns.add($newcol)
    $newcol = New-Object system.Data.DataColumn Site,([string]); $table.columns.add($newcol)
    $newcol = New-Object system.Data.DataColumn Forest,([string]); $table.columns.add($newcol)
    $newcol = New-Object system.Data.DataColumn OperationMasterRoles,([Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]); $table.columns.add($newcol)
    $newcol = New-Object system.Data.DataColumn DriveLetters,([string]); $table.columns.add($newcol)
    $newcol = New-Object system.Data.DataColumn 'Disk Used (GB)',([string]); $table.columns.add($newcol)
    $newcol = New-Object system.Data.DataColumn 'Disk Free (GB)',([string]); $table.columns.add($newcol)
     
    $row = $table.NewRow()
    $row.Hostname= $adinfo.Hostname
    $row.GlobalCatalog= $adinfo.isGlobalCatalog
    $row.Site= $adinfo.Site
    $row.Forest= $adinfo.Forest
    $row.Site= $adinfo.Site
    $row.OperationMasterRoles= [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]($adinfo.OperationMasterRoles -join "`n")
    $row.DriveLetters= $volume.Name -join "`n"
    $row.'Disk Free (GB)' = $volume_free.Free -join "`n"
    $row.'Disk Used (GB)'= $volume_used.Used -join "`n"
    $table.Rows.Add($row)
     
    $table | Select-Object Hostname,GlobalCatalog,Site,Forest,@{Name = 'OperationMasterRoles'; Expression = {$_.OperationMasterRoles -join "`n" }},DriveLetters,'Disk Free (GB)','Disk Used (GB)' | export-csv cs-idp-dcinfo.csv -NoTypeInformation
    
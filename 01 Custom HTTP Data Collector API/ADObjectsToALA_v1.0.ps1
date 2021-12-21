<#
.SYNOPSIS 
    This PowerShell script send data to Azure Log Analytics in Custom Log format.
    

.DESCRIPTION
    The script will get AD Objects from Domain Controllers specified in domainList.csv file for consumption by Microsoft Sentinel and Azure Workbooks.

.REQUIREMENTS
    - $domainlist: "domainList.csv" file which contains two columns: "domain" and "isLAPSDeployed" (0-LAPSNotDeployed; 1-LAPSDeployed)
        Format
            dc,isLAPSDeployed
            DomainControllerFQDN,1 
    - LAWorkspace: Microsoft Sentinel workspace where the information will be sent.


.DOCUMENTATION
    - Send log data to Azure Monitor with the HTTP Data Collector API: https://docs.microsoft.com/es-es/azure/azure-monitor/platform/data-collector-api
    - create the source for eventlog: https://devblogs.microsoft.com/scripting/how-to-use-powershell-to-write-to-event-logs/

.NOTES
    Script Name:ADObjectsToALA_v1.0
    AUTHOR:   Diego Martinez Rellan (dmrellan)
    VERSION:  1.0
    LASTEDIT: December 21st, 2021
.HISTORY
    
#>
        
# **********************************************************************************************************
# PARAMETERS
# **********************************************************************************************************
$domainlist = 'C:\VASW\VASWDataToSentinel\domainList.csv' # "DomainList.csv" file which contains two columns: "domain" and "isLAPSDeployed" (0-LAPSNotDeployed; 1-LAPSDeployed)
$adminauditGroup = 'Domain Admins'     # Group of Admins, used in User Hygiene report and other reports to indicate Admin account. Change the name of the group as defined in customer’s environment     
$pawAuditGroup   = 'PAWComputers'      # Group of PAW computers, used in Computer Hygiene report - column “isPAW”. Change the name of the group as defined in customer’s environment
$PawAudit        = 1                   # 0-NotUsePAW; 1-UsePAW
$AdminAudit      = 1                   # 0-NotAudit; 1-Audit

# Azure Log Analytics workspace where the information will be sent.
    $WorkspaceId = "" # WorkspaceId
    $SharedKey = "" #PrimaryKey
    
    # Custom Logs where the info will be stored
    $adminauditCL = "VASW_adminaudit_CL"
    $computersCL  = "VASW_computers_CL"
    $groupsCL     = "VASW_groups_CL"
    $pawauditCL   = "VASW_pawaudit_CL"
    $usersCL      = "VASW_users_CL"
    
    # TimeStamp used in Post-LogAnalyticsData function as TimeGenerated field
    $TimeStampField = ([DATETIME]::Now).ToUniversalTime()


# **********************************************************************************************************
# FUNCTIONS
# **********************************************************************************************************

Function Get-data-users ($Element) 
{
    #Fields accountExpires,adminCount,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,Surname,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp 
    
    $data = @{
    'accountExpires' = [string]$Element.accountExpires
    'adminCount' = [string]$Element.adminCount
    'DistinguishedName' = [string]$Element.DistinguishedName
    'Enabled' = [string]$Element.Enabled
    'GivenName' = [string]$Element.GivenName
    'msDS-PrincipalName' = [string]$Element.("msDS-PrincipalName")
    'Name' = [string]$Element.Name
    'ObjectClass' = [string]$Element.ObjectClass
    'ObjectGUID' = [guid]$Element.ObjectGUID
    'pwdLastSet' = [string]$Element.pwdLastSet
    'SamAccountName' = [string]$Element.SamAccountName
    'SID' = [string]$Element.SID
    'Surname' = [string]$Element.Surname
    'userAccountControl' = [string]$Element.userAccountControl
    'UserPrincipalName' = [string]$Element.UserPrincipalName
    'whenChanged' = [string]$Element.whenChanged
    'whenCreated' = [string]$Element.whenCreated
    'lastLogonTimestamp' = [string]$Element.lastLogonTimestamp
    }
    
    $data #| ConvertTo-Json
}
Function Get-data-computers ($Element,$isLAPSDeployed) 
{
    #LAPS
    #Fields ms-Mcs-AdmPwdExpirationTime, accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated
                                       
    #NO LAPS
    #Fields accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated
   
    $data = @{
        'accountExpires' = [string]$Element.accountExpires
        'DistinguishedName' = [string]$Element.DistinguishedName
        'DNSHostName' = [string]$Element.DNSHostName
        'Enabled' = [string]$Element.Enabled
        'lastLogonTimestamp' = [string]$Element.lastLogonTimestamp
        'msDS_PrincipalName' = [string]$Element.("msDS-PrincipalName")
        'Name'= [string]$Element.Name
        'ObjectClass' = [string]$Element.ObjectClass
        'ObjectGUID' = [guid]$Element.ObjectGUID
        'OperatingSystem' = [string]$Element.OperatingSystem
        'primaryGroupID' = [string]$Element.primaryGroupID
        'pwdLastSet' = [string]$Element.pwdLastSet
        'SamAccountName' = [string]$Element.SamAccountName
        'SID' = [string]$Element.SID
        'userAccountControl' = [string]$Element.userAccountControl
        'UserPrincipalName' = [string]$Element.UserPrincipalName
        'whenChanged' = [string]$Element.whenChanged
        'whenCreated' = [string]$Element.whenCreated
    }

    If ($isLAPSDeployed -eq 1) 
    {
        $data.add('ms-Mcs-AdmPwdExpirationTime',[string]$Element.("ms-Mcs-AdmPwdExpirationTime"))
    }
    
    $data #| ConvertTo-Json
}
Function Get-data-groups ($Element) 
{
    #Fields DistinguishedName,GroupCategory,msDS-PrincipalName,Name,ObjectGUID,SamAccountName,SID,adminCount
        
    $data = @{
    'DistinguishedName' = [string]$Element.DistinguishedName
    'GroupCategory' = [string]$Element.GroupCategory
    'msDSPrincipalName' = [string]$Element.("msDS-PrincipalName")
    'Name' = [string]$Element.Name
    'ObjectGUID' = [guid]$Element.ObjectGUID
    'SamAccountName' = [string]$Element.SamAccountName
    'SID' = [string]$Element.SID
    'adminCount' = [string]$Element.adminCount
    }
    
    $data #| ConvertTo-Json
}
Function Get-data-pawaudit ($Element) 
{
    #Fields distinguishedName
    
    $data = @{
    'distinguishedName' = [string]$Element.distinguishedName
    }
    
    $data #| ConvertTo-Json
}
Function Get-data-adminaudit ($Element) 
{
    #Fields distinguishedName
    
    $data = @{
    'distinguishedName' = [string]$Element.distinguishedName
    }
    
    $data #| ConvertTo-Json
}

# Create the function to create the authorization signature
Function Build-Signature ($WorkspaceId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $WorkspaceId,$encodedHash
    return $authorization
}
# Create the function to create and post the request
Function Post-LogAnalyticsData($WorkspaceId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -WorkspaceId $WorkspaceId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $WorkspaceId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    


    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}


# **********************************************************************************************************
# MAIN 
# **********************************************************************************************************
#------- Init -----------------
$domains = Import-Csv $domainlist
$Users,$Groups,$Computers,$PawAuditList,$AdminAuditList = @()


ForEach ($domain in $domains) {
    # Users section ----------------------------
    $Users=Get-ADUser -Filter * -Server $domain.dc -Properties accountExpires,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,Surname,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp,adminCount | Select-Object accountExpires,adminCount,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,Surname,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp 
        $arrayRegs = @()
        for ($j=0; $j -lt $Users.count; $j++)
        {
            $reg = Get-data-users -Element $Users[$j]
            $arrayRegs += $reg
        } 
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status=Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $usersCL
        $rows=$j
        #write-output  "USERS: `n`tResponse status code: $status `n`tUsers: $rows`n`tCustom Log: ""$usersCL"""
        Write-EventLog –LogName Application –Source “VASWDataToSentinel” –EntryType Information –EventID 1919 –Message "USERS: `n`tResponse status code: $status `n`tUsers: $rows`n`tCustom Log: ""$usersCL"""


    # Computers section -----------------------
    If ($domain.isLAPSDeployed -gt 0) {
        $Computers = Get-ADComputer -Filter * -Server $domain.dc -Properties ms-Mcs-AdmPwdExpirationTime, accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated | Select-Object ms-Mcs-AdmPwdExpirationTime, accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated
        
    }
    Else {
        $Computers = Get-ADComputer -Filter * -Server $domain.dc -Properties accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated | Select-Object accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated
    }
        $arrayRegs = @()
        for ($j=0; $j -lt $Computers.count; $j++)
        {
            $reg = Get-data-computers -Element $Computers[$j] -isLAPSDeployed $domain.isLAPSDeployed
            $arrayRegs += $reg
        } 
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status=Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $computersCL
        $rows=$j
        $LAPS=$domain.isLAPSDeployed
        #write-output  "COMPUTERS: `n`tResponse status code: $status `n`tComputers: $rows `n`tCustom Log: ""$computersCL"""
         Write-EventLog –LogName Application –Source “VASWDataToSentinel” –EntryType Information –EventID 1919 –Message "COMPUTERS: `n`tResponse status code: $status `n`tComputers: $rows `n`tCustom Log: ""$computersCL"""
        
    

    # Groups section ------------------------
    $Groups=Get-ADGroup -Filter * -Server $domain.dc -Properties adminCount, msDS-PrincipalName, samaccountName | Select-Object DistinguishedName,GroupCategory,msDS-PrincipalName,Name,ObjectGUID,SamAccountName,SID,adminCount
        $arrayRegs = @()
        for ($j=0; $j -lt $Groups.count; $j++)
        {
            $reg = Get-data-groups -Element $Groups[$j] 
            $arrayRegs += $reg
        } 
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status=Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $groupsCL
        $rows=$j
        #write-output  "GROUPS: `n`tResponse status code: $status `n`tGroups: $rows `n`tCustom Log: ""$groupsCL"""
         Write-EventLog –LogName Application –Source “VASWDataToSentinel” –EntryType Information –EventID 1919 –Message "GROUPS: `n`tResponse status code: $status `n`tGroups: $rows `n`tCustom Log: ""$groupsCL"""


    # PawAudit section -----------------------
    If ($PawAudit -gt 0) {
        $PawAuditList = @()
        $PawAuditList += Get-ADGroupMember -Identity $pawAuditGroup -Server $domain.dc -Recursive | Select-Object distinguishedName 
        $arrayRegs = @()
        for ($j=0; $j -lt $PawAuditList.count; $j++)
        {
            $reg = Get-data-pawaudit -Element $PawAuditList[$j] 
            $arrayRegs += $reg
        } 
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status=Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $pawauditCL
        $rows=$j
        #write-output  "PAWAUDIT: `n`tResponse status code: $status `n`tPawAudit: $rows `n`tCustom Log: ""$pawauditCL"""
         Write-EventLog –LogName Application –Source “VASWDataToSentinel” –EntryType Information –EventID 1919 –Message "PAWAUDIT: `n`tResponse status code: $status `n`tPawAudit: $rows `n`tCustom Log: ""$pawauditCL"""
    }

    # AdminAudit section ---------------------
    If ($AdminAudit -gt 0) {
        $AdminAuditList = @()
        $AdminAuditList += Get-ADGroupMember -Identity $adminAuditGroup -Server $domain.dc | Select-Object distinguishedName 
        
        $arrayRegs = @()
        for ($j=0; $j -lt $AdminAuditList.count; $j++)
        {
            $reg = Get-data-adminaudit -Element $AdminAuditList[$j] 
            $arrayRegs += $reg
        } 
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status=Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $adminauditCL
        $rows=$j
        #write-output  "ADMINAUDIT: `n`tResponse status code: $status `n`tAdminAudit: $rows `n`tCustom Log: ""$adminauditCL"""
        Write-EventLog –LogName Application –Source “VASWDataToSentinel” –EntryType Information –EventID 1919 –Message "ADMINAUDIT: `n`tResponse status code: $status `n`tAdminAudit: $rows `n`tCustom Log: ""$adminauditCL"""
    }
}


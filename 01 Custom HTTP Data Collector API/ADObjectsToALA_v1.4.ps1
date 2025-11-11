<#
.SYNOPSIS 
    This PowerShell script send data to Azure Log Analytics in Custom Log format
    

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
        - Data limits: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api#data-limits
    - create the source for eventlog: https://devblogs.microsoft.com/scripting/how-to-use-powershell-to-write-to-event-logs/

.NOTES
    Script Name:ADObjectsToALA_v1.4
    AUTHOR:   Diego Martinez Rellan (dmrellan)
    VERSION:  1.4
    LASTEDIT: November 2025
.HISTORY
    
#>
        
# **********************************************************************************************************
# PARAMETERS
# **********************************************************************************************************
$domainlist = 'C:\VASW\VASWDataToSentinelAMAbased\domainList.csv' # "DomainList.csv" file which contains two columns: "domain" and "isLAPSDeployed" (0-LAPSNotDeployed; 1-LAPSDeployed)
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

# Parameters to control data limits
$maxElements=10000 # 10k elements per data collector api post


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
Function Get-data-gMSA ($Element) 
{
    #Fields accountExpires,adminCount,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,Surname,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp 
    Write-Host ${$Element.msDS-ManagedPasswordInterval}
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
    'userAccountControl' = [string]$Element.userAccountControl
    'UserPrincipalName' = [string]$Element.UserPrincipalName
    'whenChanged' = [string]$Element.whenChanged
    'whenCreated' = [string]$Element.whenCreated
    'lastLogonTimestamp' = [string]$Element.lastLogonTimestamp
    'msDS-ManagedPasswordInterval' = [string]$Element.("msDS-ManagedPasswordInterval")
    'PrincipalsAllowedToRetrieveManagedPassword' = [string] $Element.PrincipalsAllowedToRetrieveManagedPassword
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
    # if proxy needed: https://bycode.dev/2019/08/22/how-to-use-powershell-invoke-webrequest-behind-corporate-proxy/
    return $response.StatusCode
}


# **********************************************************************************************************
# MAIN 
# **********************************************************************************************************
#------- Init -----------------
$domains = Import-Csv $domainlist
$Users,$gMSAs,$Groups,$Computers,$PawAuditList,$AdminAuditList = @()

Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1900 -Message "ADObjectsToALA_v1.2.ps1 script STARTED"
ForEach ($domain in $domains) {
    # ******************************************************************************************************************************
    # USERS SECTION ----------------------------------------------------------------------------------------------------------------
    # ******************************************************************************************************************************
    $Users=Get-ADUser -Filter * -Server $domain.dc -Properties accountExpires,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,Surname,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp,adminCount | Select-Object accountExpires,adminCount,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,Surname,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp 
    ## Data Limits: Maximum of 30 MB per post to Azure Monitor Data Collector API. 
    $j=0
    $i=0

    # If the number of elements is over 10k this part split the Post to log analytics in different posts with 10k elements as maximum
    while ($j -lt $Users.count)
    {
        $arrayRegs = @()
        for ($i=0; $i -lt $maxElements; $i++)
        {
                
            $reg = Get-data-users -Element $Users[$j]
            $arrayRegs += $reg
            $j++
            if ($j -eq $users.count){break}
        }
        
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status = Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $usersCL
        $rows = $arrayRegs.count
        Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 19191 -Message "USERS SECTION: `n`nDomain: $domain `nResponse status code: $status `nIterating users: $rows users `nCustom Log: ""$usersCL"""

    }
    $rows=$j
    Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1919 -Message "USERS SECTION: `n`nDomain: $domain `nResponse status code: $status `nTOTAL users: $rows users `nCustom Log: ""$usersCL"""

    # ******************************************************************************************************************************
    # GROUP MANAGED SERVICE ACCOUNTS -----------------------------------------------------------------------------------------------
    # ******************************************************************************************************************************
    
    $gMSAs=Get-ADServiceAccount -Filter * -Properties accountExpires,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp,adminCount,msDS-ManagedPasswordInterval,PrincipalsAllowedToRetrieveManagedPassword | Select-Object accountExpires,adminCount,DistinguishedName,Enabled,GivenName,msDS-PrincipalName,Name,ObjectClass,ObjectGUID,pwdLastSet,SamAccountName,SID,userAccountControl,UserPrincipalName,whenChanged,whenCreated,lastLogonTimestamp,msDS-ManagedPasswordInterval,PrincipalsAllowedToRetrieveManagedPassword
    ## Data Limits: Maximum of 30 MB per post to Azure Monitor Data Collector API. 
    $j=0
    $i=0

    # If the number of elements is over 10k this part split the Post to log analytics in different posts with 10k elements as maximum
    while ($j -lt $gMSAs.count)
    {
        $arrayRegs = @()
        for ($i=0; $i -lt $maxElements; $i++)
        {
                
            $reg = Get-data-gmsa -Element $gMSAs[$j]
            $arrayRegs += $reg
            $j++
            if ($j -eq $gMSAs.count){break}
        }
        
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status = Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $usersCL
        $rows = $arrayRegs.count
        Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 19191 -Message "gMSA: `n`tResponse status code: $status `n`tIteration gMSAs: $rows `n`tCustom Log: ""$usersCL"""

    }
    $rows=$j
    Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1919 -Message "gMSA: `n`tResponse status code: $status `n`tTotal gMSA: $rows`n`tCustom Log: ""$usersCL"""


    # ******************************************************************************************************************************
    # COMPUTERS SECTION ------------------------------------------------------------------------------------------------------------
    # ******************************************************************************************************************************
    If ($domain.isLAPSDeployed -gt 0) {
        $Computers = Get-ADComputer -Filter * -Server $domain.dc -Properties ms-Mcs-AdmPwdExpirationTime, accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated | Select-Object ms-Mcs-AdmPwdExpirationTime, accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated
        
    }
    Else {
        $Computers = Get-ADComputer -Filter * -Server $domain.dc -Properties accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated | Select-Object accountExpires, DistinguishedName, DNSHostName, Enabled, lastLogonTimestamp, msDS-PrincipalName, Name, ObjectClass, ObjectGUID, OperatingSystem, primaryGroupID, pwdLastSet, SamAccountName,SID, userAccountControl, UserPrincipalName, whenChanged, whenCreated
    }
    $j=0
    $i=0

    # If the number of elements is over 15k this part split the Post to log analytics in different posts with 15k elements as maximum
    while ($j -lt $Computers.count)
    {
        $arrayRegs = @()
        for ($i=0; $i -lt $maxElements; $i++)
        {
                
            $reg = Get-data-computers -Element $Computers[$j] -isLAPSDeployed $domain.isLAPSDeployed
            $arrayRegs += $reg
            $j++
            if ($j -eq $Computers.count){break}
        }
        $json = ConvertTo-Json -InputObject $arrayRegs

        $status=Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $computersCL
        $LAPS=$domain.isLAPSDeployed
        $rows=$arrayRegs.count
        Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 19201 -Message "COMPUTERS SECTION: `n`nDomain: $domain `nResponse status code: $status `nIterating computers: $rows computers `nCustom Log: ""$computersCL"""

    }
    $rows=$j
    $LAPS=$domain.isLAPSDeployed
    #write-output  "COMPUTERS: `n`tResponse status code: $status `n`tUsers: $rows`n`tCustom Log: ""$computersCL"""
    Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1920 -Message "COMPUTERS SECTION: `n`nDomain: $domain `nLAPSDeployed: $LAPS (0-LAPSnotDeployed; 1-LAPSDeployed. Config in the CSV file) `nResponse status code: $status `nTOTAL computers: $rows computers `nCustom Log: ""$computersCL"""
        

    # ******************************************************************************************************************************
    # GROUPS SECTION ---------------------------------------------------------------------------------------------------------------
    # ******************************************************************************************************************************
    $Groups=Get-ADGroup -Filter * -Server $domain.dc -Properties adminCount, msDS-PrincipalName, samaccountName | Select-Object DistinguishedName,GroupCategory,msDS-PrincipalName,Name,ObjectGUID,SamAccountName,SID,adminCount
    ## Data Limits: Maximum of 30 MB per post to Azure Monitor Data Collector API. 
    $j=0
    $i=0
    
    # If the number of elements is over $maxElements this section split the Post to log analytics in different posts with $maxElements elements as maximum
    while ($j -lt $Groups.count)
    {
        $arrayRegs = @()
        for ($i=0; $i -lt $maxElements; $i++)
        {
            $reg = Get-data-groups -Element $Groups[$j] 
            $arrayRegs += $reg
            $j++
            if ($j -eq $Groups.count){break}
        }
         
        $json = ConvertTo-Json -InputObject $arrayRegs
        $status = Post-LogAnalyticsData -WorkspaceId $WorkspaceId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $groupsCL
        $rows = $arrayRegs.count
        Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 19211 -Message "GROUPS SECTION: `n`nDomain: $domain `nResponse status code: $status `nIterating groups: $rows `nCustom Log: ""$groupsCL"""
    }
    $rows = $j
    Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1921 -Message "GROUPS SECTION: `nDomain: $domain `nResponse status code: $status `nTOTAL Groups: $rows`nCustom Log: ""$groupsCL"""

    
    # ******************************************************************************************************************************
    # PAWAUDIT SECTION -------------------------------------------------------------------------------------------------------------
    # ******************************************************************************************************************************
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
         Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1922 -Message "PAWAUDIT SECTION: `n`nDomain: $domain `nResponse status code: $status `nPawAudit: $rows `nCustom Log: ""$pawauditCL"""
    }


    # ******************************************************************************************************************************
    # ADMINAUDIT SECTION -----------------------------------------------------------------------------------------------------------
    # ******************************************************************************************************************************
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
        Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1923 -Message "ADMINAUDIT SECTION: `n`nDomain: $domain `nResponse status code: $status `nAdminAudit: $rows `nCustom Log: ""$adminauditCL"""
    }
}
Write-EventLog -LogName Application -Source "VASWDataToSentinel" -EntryType Information -EventId 1900 -Message "ADObjectsToALA_v1.3.ps1 script FINISHED"



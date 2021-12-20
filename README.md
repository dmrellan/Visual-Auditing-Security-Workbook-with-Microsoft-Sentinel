# Visual Auditing Security Workbook with Microsoft Sentinel

## Overvew

The _Visual Auditing Security Workbook_ project is a set of tabs in an Azure Workbook for Microsoft Sentinel that pulls information from the Security Events of your Active Directory (Domain Controllers) and a custom HTTP Data Collector API and enables security teams to quickly detect insights about their Active Directory configuration, operations, and risks.

The current Visual Auditing Security Workbook includes 11 different tabs to discover information about different scenarios:

![image](https://user-images.githubusercontent.com/35997289/146782431-46aba436-71bc-452f-89c8-d3380562e59d.png)

- **Active Directory user hygiene**: This tab shows the overall state of the user population based on high-privilege users, users that have not logged in for an extended period, users that have not changed the password for an extended period, and users with Password Never Expired set.
- **Active Directory computer hygiene**: This tab shows which computers within the domain are active with logins. It will present computers based on the Operating System version, with stale logins and passwords.
- **LAPS deployment**: Local Administrative Password Solution (LAPS) tab shows how many computers have been configured by the LAPS solution. It will show which Operating Systems have LAPS deployed and the up-to-dateness vector on the LAPS Password.
- **LAPS audit**: This tab shows which users retrieve the passwords for the local systems to use locally. LAPS Auditing helps unveil which user account has accessed the local administrator’s password of a given computer.
- **Non-Existent users activity**: This tab tracks the non-existent and potentially “sprayed” accounts in your environment. These are accounts generating failed logins (4625s) in which the sub-status code references a non-existent account. (Note: these failed logins are distinct from existing accounts with incorrect passwords.) You should look especially for machines hosting – or accounts exhibiting – a pattern of non-existent user types of failed logins. These can be early indicators of attack or attempted attack.
- **Active Directory Group Changes (adds and removes)**: This tab will show which groups have been changed. It will also show which users are making the most number of changes.
- **User authentication activity**: This tab will show which users are authenticating. It gives an overview of the authentication being performed by a specific user.
- **Use of Schannel**: This tab will show where Schannel authentication is occurring. It will show which computer that was initiating the Schannel authentication. You will need to temporarily install the MMA on the webserver or whatever server you suspect is using SSL or another deprecated encryption method. Then you will be able to see the actual cipher suite used and remediate the deprecated ones in use.
- **Security Event Log clears**: This tab shows where the security log has been cleared and by which user.
- **Active Directory Advanced Audit Policy Changes**: This tab shows an attacker’s attempts to cover his tracks as he potentially has created environmental persistence
- **User Management Activity**: This tab shows the most common user management activities within the forest. User Management in a typical environment is relatively static and does not change much unless something is altered.
 
**Note**: We recommend using this workbook together with the Insecure Protocols workbook of Microsoft Sentinel to identify their use and help remove Insecure Protocols from your Active Directory and Azure Active Directory.

## Requirements
To be able to use all scenarios of this workbook, you will need to meet the following requirements:
1. Have an enabled Azure Subscription with a **Microsoft Sentinel workspace**.
2. Create a new Group Policy Object to enable the necessary **audit policies** and **registry keys** in your Active Directory (applied to Domain Controllers).
3. Configure SACL for **Auditing LAPS**
4. Enable **all Microsoft Defender for Cloud plans** in the Log Analytics with Microsoft Sentinel enabled and configure "All events" in data collection.
5. Provide a server to deploy the **Log Analytics Gateway** and configure the **PowerShell script** to populate custom logs.
6. **Connect** your Domain Controllers to Microsoft Sentinel throughout a Log Analytics Gateway.

## Deployment steps

### 1 - Audit policies and registry keys configuration in Domain Controllers

#### Advanced Audit Policies
Configure a new GPO applied to your domain controllers to enable the following audit policies:

**Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies**
- **\DS Access**
  - Active Directory Services Access - _Success_
- **\Account Logon**
  - Audit Credential Validation - _Success, Failure_
  - Audit Kerberos Authentication Service - _Success, Failure_
  - Audit Kerberos Service Ticket Operations - _Success, Failure_
- **\Account Management**
  - Audit Security Group Management - _Success, Failure_
  - Audit User Account Management - _Success, Failure_
- **\Logon/Logoff**
  - Audit Logon - _Success, Failure_
  - Audit Account Lockout - _Success, Failure_
  - Audit Other Logon/Logoff Events - _Success, Failure_

#### Registry Keys
Enable Schannel events:
- HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\EventLogging
  - Change the value to **7**

### 2 - Audit LAPS password retrievals: Configure SACL
1. Open Active Directory Users and Computers
2. Enable **View\Advanced View**
3. Select root of the domain
4. Open **Properties** and go to the **Security** tab.
5. Click the **Advanced** button and go to **auditing** tab.
6. Click **add** to add a new entry.
7. Change the Principal to **Eveyone**, type to **Success**, Applies to **Descendant Computer objects**.
8. Click **Clear all** at the bottom to uncheck all the prechecked items.
9. Check the box **all extended rights**.
10. Check the box **Read ms-Mcs-AdmPwd**.
11. Click **ok** and close out of all the security properties.

### 3 - Microsoft Sentinel: Configure AD integration and events collection
#### Active Directory Integration
1. Go to your Microsoft Sentinel > Settings > Workspace Settings > Computer Groups > Active Directory and check the Import active directory group memberships from computers.
2. Click Apply.

#### Events Collection
1. Go to your Microsoft Sentinel > Settings > Workspace Settings > Agents configuration
2. Click +Add windows event log and write System
3. Click on Information box to collect only the Information Events from System log and the apply.

#### Microsoft Defender for Cloud
1. Enable all Microsoft Defender for Cloud plans in the Log Analytics with Microsoft Sentinel enabled
2. Go to Microsoft Defender for Cloud
3. Go to Environment Settings and expand your tenant and azure subscriptions until find your Log Analytics workpsace with Microsoft Sentinel enabled.
4. Click on your Log Analytics with Microsoft Sentinel enabled.
5. Go to Defender plans and click on "Enable all Microsoft Defender for Cloudo plans"
6. Click on save.
7. Go to Data collection.
8. Cllick on All events and save.

### 4 - Connect your Domain Controllers to Microsoft Sentinel
1. On your privided server, deploy the Log Analytics Gateway software and connect it to Microsoft Sentinel.
 - Download the Log Analytics Gateway software from your workspace going to Microsoft Sentinel > Settings > Workspace Settings > Agents management > Log Analytics Gateway
 - Install the Log Analytics Gateway.The log analytics gateway needs access to the 4 endpoints described here in Firewall requirements: https://docs.microsoft.com/en-us/azure/azure-monitor/platform/log-analytics-agent
 - Install the Microsoft Monitoring Agent on Log Analytics Gateway and connect it to the Microsoft Sentinel with the Workspace Id and Primary key that you will find on Microsoft Sentinel > Settings > Workspace Settings > Agents management.
2. Install the Microsoft Monitoring Agent in your Domain Controllers and connected them to your Microsoft Sentinel throught Log Analtyics Gateway with the Workspace Id and Primary key that you will find on Microsoft Sentinel > Settings > Workspace Settings > Agents management. You will need to configure the Log Analytics Gateway in the Proxy Setting tab of each Domain Controller.

### 5 - Setup the PowerShell script to populate Custom Logs
1. Install the RSAT AD DS Powershell module in the provided server (Log Analytics Gateway).
 - Open an elevated powershell console and run the command Install-windowsfeature RSAT-AD-PowerShell
2. Use the ADObjectsToALA_v1.0.ps1 and domainlist.csv.
3. Modify the paramters section of ADObjectsToALA_v1.0.ps1 and domainlist.csv to adapt them to your environment.
 - Domainlist.csv needs to be manually created and should contain: Headers line (dc,isLAPSDeployed) and one Domain Controller name and isLAPSDeployed value (comma separated) per line from each domain in scope.
4. Create a scheduled task to re-run the script daily.

### 6 - Create the Log Analytics Parser Funtions in your Microsoft Sentinel
Create the following Log Analytics Functions in your Log Analytics with Microsoft Sentinel enabled based on the provieded kusto files in Log Analytics Parser functions folder:
- VASWAdminAuditParser
- VASWComputersParser
- VASWGroupParser
- VASWPawAuditParser
- VASWUsersParser

### 7 - Import the Visual Auditing Security Workbook
1. Go to Microsoft Sentinel > Workbooks
2. Click on Add workbook
3. Click on edit and go to Advanced Editor
4. Remove the default workbook code and paste the code of Visual Auditing Security Workbook.workbook
5. Click apply
6. Configure the parameters:
 - Log Analytics workspace.
 - Time Range
 - Ms-MCS-AdmPwd in LAPS audit tab. You can get your ms-mcs-admpwd by running the following code:
    
    <pre><code>$rootdse = Get-ADRootDSE
    $GUIDs = Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID
    ForEach ($Guid in $Guids)
    {
		    If ($guid.lDAPDisplayName -Like "*ms-mcs-admpwd")
      {
		      $SGuid = ([System.GUID]$guid.SchemaIDGuid).Guid
		      Write-host $guid.lDAPDisplayName, ([System.GUID]$guid.SchemaIDGuid)
		    }
    }
    </code></pre>


## Author
The Visual Auditing Security Workbook was developed by **Diego Martínez Rellán (dmrellan) - Microsoft**. It is inspired by the Visual Auditing Security Toolkit (VAST) service from Microsoft Support (currently retired) developed by Brian Delaney and Jon Shectman.

## Acknowledgment
Special thanks to my co-worker Alvaro Jiménez Contreras for his help during the evaluation of this solution's development tasks and test phase.


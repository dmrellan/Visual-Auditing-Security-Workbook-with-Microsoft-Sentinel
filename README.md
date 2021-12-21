# Visual Auditing Security Workbook with Microsoft Sentinel

## Overvew

The _Visual Auditing Security Workbook_ project is a set of scenarios in an Azure Workbook for Microsoft Sentinel that pulls information from your Active Directory Domain Controllers and enables security teams to quickly detect insights about their Active Directory configuration, operations, and risks.

![Scenario](https://user-images.githubusercontent.com/35997289/146847937-ff196df8-82f5-4953-87a5-783b7fd4fd58.jpg)

This workbook visualizes information from two Data Sources:
- **Security Events** from Domain Controllers (Microsoft Defender for Cloud plans) and common **Events**.
- Data sent by a **Custom HTTP Data Collector API**. (Custom Logs format)


The current Visual Auditing Security Workbook includes 11 scenarios below:

![image](https://user-images.githubusercontent.com/35997289/146782431-46aba436-71bc-452f-89c8-d3380562e59d.png)

- **User Hygiene**: Shows the overall state of the user population based on high-privilege users, users that have not logged in for an extended period, users that have not changed the password for an extended period, and users with Password Never Expired set.
- **Computer Hygiene**: Shows which computers within the domain are active with logins. It will present computers based on the Operating System version, with stale logins and passwords.
- **LAPS Deploy**: Local Administrative Password Solution (LAPS) Deploy tab shows how many computers have been configured by the LAPS solution. It will show which Operating Systems have LAPS deployed and the up-to-dateness vector on the LAPS Password.
- **LAPS Audit**: This tab shows which users retrieve the passwords for the local systems to use locally. LAPS Auditing helps unveil which user account has accessed the local administrator’s password of a given computer.
- **Non-Existent users activity**: This tab tracks the non-existent and potentially _sprayed_ accounts in your environment. These are accounts generating failed logins (4625s) in which the sub-status code references a non-existent account. (Note: these failed logins are distinct from existing accounts with incorrect passwords). You should look especially for machines hosting – or accounts exhibiting – a pattern of non-existent user types of failed logins. These can be early indicators of attack or attempted attack.
- **Group Changes**: This tab will show which Active Directory Groups have been changed. It will also show which users are making the most number of changes.
- **User Authentication**: This tab will show which users are authenticating. It gives an overview of the authentication being performed by a specific user.
- **SChannel**: This tab will show where SChannel authentication is occurring. It will show which computer that was initiating the Schannel authentication. You will need to temporarily install the MMA on the webserver or whatever server you suspect is using SSL or another deprecated encryption method. Then you will be able to see the actual cipher suite used and remediate the deprecated ones in use.
- **Security Log Clear**: This tab shows where the security log has been cleared and by which user.
- **Audit Policy Changes**: This tab shows an attacker’s attempts to cover his tracks as he potentially has created environmental persistence
- **User Management**: This tab shows the most common user management activities within the forest. User Management in a typical environment is relatively static and does not change much unless something is altered.
 
**Note**: We recommend using this workbook together with the **Insecure Protocols** workbook of Microsoft Sentinel to identify their use and help remove Insecure Protocols from your Active Directory and Azure Active Directory.

## Requirements
To be able to use all scenarios of this workbook, you will need to meet the following requirements:
1. Have an enabled Azure Subscription with a **Microsoft Sentinel workspace**.
2. Create a new Group Policy Object to enable the necessary **audit policies** and **registry keys** in your Active Directory (applied to Domain Controllers).
3. Configure SACL for **Auditing LAPS**
4. Enable **all Microsoft Defender for Cloud plans** in the Microsoft Sentinel workspace and configure "All events" in data collection.
5. Deploy a server to act as **Log Analytics Gateway** and run the **Custom HTTP Data Collector API (PowerShell script)**.
6. **Connect** your Domain Controllers to Microsoft Sentinel throughout a Log Analytics Gateway by deploying the Microsoft Monitoring Agent.

## Deployment steps

### 1 - Advanced audit policies and registry keys configuration in Domain Controllers.

#### Advanced Audit Policies
To generate the Security Events which will be collected and shown in the workbook, it is needed to configure a new GPO, applied to Domain Controllers, to enable the following audit policies:

**Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\**
- **DS Access**
  - Active Directory Services Access - _Success_
- **Account Logon**
  - Audit Credential Validation - _Success, Failure_
  - Audit Kerberos Authentication Service - _Success, Failure_
  - Audit Kerberos Service Ticket Operations - _Success, Failure_
- **Account Management**
  - Audit Security Group Management - _Success, Failure_
  - Audit User Account Management - _Success, Failure_
- **Logon/Logoff**
  - Audit Logon - _Success, Failure_
  - Audit Account Lockout - _Success, Failure_
  - Audit Other Logon/Logoff Events - _Success, Failure_

#### Registry Keys
To generate the Events related with SChannel user, it is needed to configure the following registry key:
- **HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\EventLogging**
  - Change the value to **7**

### 2 - Audit LAPS password retrievals: Configure SACL
Make sure that proper audit settings (SACLs) are in place on the objects to audit. To audit LAPS password retrieval it is needed to configure the audit settings at the root of the domain.
1. Open **Active Directory Users and Computers**.
2. Enable **View\Advanced Features**.
3. Select root of the domain.
4. Open **Properties** and go to the **Security** tab.
5. Click the **Advanced** button and go to **Auditing** tab.
6. Click **Add** to add a new entry.
7. Change the Principal to **Eveyone**, type to **Success**, Applies to **Descendant Computer objects**.
8. Click **Clear all** at the bottom to uncheck all the prechecked items.
9. Check the box **all extended rights**.
10. Check the box **Read ms-Mcs-AdmPwd**.
11. Click **ok** and close out of all the security properties.
![image](https://user-images.githubusercontent.com/35997289/146851785-1904f00e-2121-414c-8ffb-723f2812f1f2.png)


### 3 - Microsoft Sentinel: Configure AD integration and events collection
Once advanced audit policies and registry keys are configured, the next step is to configure the Data Sources in Microsoft Sentinel.
#### Active Directory Integration
1. Go to your Microsoft Sentinel > Settings > Workspace Settings > Computer Groups > Active Directory and check the **Import active directory group memberships from computers**.
2. Click **Apply**.

![image](https://user-images.githubusercontent.com/35997289/146852114-fd588bbd-7ff7-4e39-8ac8-c5a8d46d0b89.png)

#### Events Collection
1. Go to your Microsoft Sentinel > Settings > Workspace Settings > Agents configuration
2. Click +Add windows event log and write **System**
3. Click on **Information** box to collect only the Information Events from System log and the apply.

![image](https://user-images.githubusercontent.com/35997289/146852267-fea98016-cb7b-4866-a435-340114823254.png)


#### Microsoft Defender for Cloud
To collecte the Security Events it is needed to enable **all Microsoft Defender for Cloud plans** in the Microsoft Sentinel workspace.
1. Go to **Microsoft Defender for Cloud**.
2. Go to Environment Settings and expand your Tenant and Azure Subscriptions until find your Log Analytics Microsoft Sentinel workspace.
3. Click on your Microsoft Sentinel workspace.
4. Go to **Defender plans** and click on **Enable all Microsoft Defender for Cloudo plans**.
5. Click on **save**.
6. Go to **Data collection**.
7. Click on **All events** and **save**.

![image](https://user-images.githubusercontent.com/35997289/146852513-c86028b3-e551-484e-b2e6-12738ff52e6e.png)

### 4 - Setup the Custom HTTP Data Collector API (PowerShell script) to populate Custom Logs.
The workbook need Active Directory Objects (users, computers, groups, etc) information to populate Hygiene and LAPS tabs. This information is collected by the custom data collector and uploaded to Microsoft Sentinel in Custom Logs format. To configure the Custom HTTP Data Collector it is needed to follow these steps:
1. Install the **RSAT AD DS Powershell module** in the Log Analytics Gateway server.Open an elevated powershell console and run the command:
<pre><code>Install-windowsfeature RSAT-AD-PowerShell</code></pre>
2. Personalize the **ADObjectsToALA_v1.0.ps1** (parameters section) and **domainlist.csv** files to your environment.
 - **Domainlist.csv**: This file needs to be manually created and should contain the headers line (dc,isLAPSDeployed) and one Domain Controller name and isLAPSDeployed value (comma separated) per line from each domain in scope.

![image](https://user-images.githubusercontent.com/35997289/146853174-529f13f6-7733-4f4f-8b63-169ea9d70f10.png)

3. Create a scheduled task to run the script **daily**.

### 5 - Create the Log Analytics Parser funtions in your Microsoft Sentinel.
After configuring the Custom HTTP Data Collector API, it is needed to create several Log Analytics Parser functions in Microsoft Sentinel. The workbook uses these functions to process the information received from the data collector and to calculate new fields based on the information collected. Parser functions need to be created precisely with these names:
- VASWUsersParser
- VASWComputersParser
- VASWGroupParser
- VASWAdminAuditParser
- VASWPawAuditParser

### 6 - Connect your Domain Controllers to Microsoft Sentinel.
To start sending events from Domain Controllers to Microsoft Sentinel, firstly it is needed to deploy the Log Analytics Gateway in the provided server to act as a gateway between Domain Controllers and Azure. Then, Microsoft Monitoring Agent will be deployed on Domain Controllers to connect to Microsoft Sentinel trought the gateway. To do that, follow these steps:
1. Download and **Install** the Log Analytics Gateway software in the provided server. This software can be downloaded from the workspace: _Microsoft Sentinel > Settings > Workspace Settings > Agents management > Log Analytics Gateway_. The Log Analytics Gateway requires access to the four endpoints described [here](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/log-analytics-agent).
	- Note: In the installation wizard you will need to introduce the Log Analytics Gateway port. This port will be used when Microsoft Monitoring Agent is installed on **Domain Controllers**, in the proxy configuration step.
2. Install the **Microsoft Monitoring Agent** in the **Log Analytics Gateway server** and connect it to the Microsoft Sentinel with the WorkspaceId and PrimaryKey which are located in _Microsoft Sentinel > Settings > Workspace Settings > Agents management_.
3. Install the **Microsoft Monitoring Agent** in **Domain Controllers** and connect them to Microsoft Sentinel throught Log Analtyics Gateway server. On each Domain Controller, Log Analytics Gateway need to be configured in the Proxy Setting tab.

### 7 - Import the Visual Auditing Security Workbook
1. Go to Microsoft Sentinel > Workbooks.
2. Click on **Add workbook**.
3. Click on edit and go to **Advanced Editor**.
4. Remove the default workbook code and paste the code of **Visual Auditing Security Workbook.workbook**
5. Click **apply**.
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


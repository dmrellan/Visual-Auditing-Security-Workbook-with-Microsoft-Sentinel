# Visual Auditing Security Workbook with Microsoft Sentinel
## Content
- [Overview](https://github.com/dmrellan/Visual-Auditing-Security-with-Microsoft-Sentinel#overvew)
- [Requirements](https://github.com/dmrellan/Visual-Auditing-Security-with-Microsoft-Sentinel#requirements)
- [Deployment steps](https://github.com/dmrellan/Visual-Auditing-Security-with-Microsoft-Sentinel#deployment-steps)
	- [1 - Advanced audit policies and registry keys configuration in Domain Controllers.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel#1---advanced-audit-policies-and-registry-keys-configuration-in-domain-controllers)
	- [2 - Audit LAPS password retrievals: Configure SACL](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel#2---audit-laps-password-retrievals-configure-sacl)
	- [3 - Microsoft Sentinel: Configure AD integration and events collection](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel#3---microsoft-sentinel-configure-ad-integration-and-events-collection)
	- [4 - Setup the Custom HTTP Data Collector API (PowerShell script) to populate Custom Logs.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel#4---setup-the-custom-http-data-collector-api-powershell-script-to-populate-custom-logs)
	- [5 - Create the Log Analytics Parser funtions in your Microsoft Sentinel.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel#5---create-the-log-analytics-parser-funtions-in-your-microsoft-sentinel)
	- [6 - Connect your Domain Controllers to Microsoft Sentinel.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel#6---connect-your-domain-controllers-to-microsoft-sentinel)
	- [7 - Import the Visual Auditing Security Workbook](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel#7---import-the-visual-auditing-security-workbook)
- [Author](https://github.com/dmrellan/Visual-Auditing-Security-with-Microsoft-Sentinel#author)
- [Acknowledgment](https://github.com/dmrellan/Visual-Auditing-Security-with-Microsoft-Sentinel#acknowledgment)

## Overview

The _Visual Auditing Security Workbook_ project is a set of scenarios in an Azure Workbook for Microsoft Sentinel that pulls information from your Active Directory Domain Controllers and enables security teams to quickly detect insights about their Active Directory configuration, operations, and risks.

This workbook visualizes information from two Data Sources:
- **Security Events** from Domain Controllers and common **Events**.
- Data sent by a **Custom HTTP Data Collector API**. (Custom Logs format)


The current Visual Auditing Security Workbook includes 11 scenarios below:

![image](https://user-images.githubusercontent.com/35997289/146782431-46aba436-71bc-452f-89c8-d3380562e59d.png)

1 - **User Hygiene**: Shows the overall state of the user population based on high-privilege users, users that have not logged in for an extended period, users that have not changed the password for an extended period, and users with Password Never Expired set.
![image](https://user-images.githubusercontent.com/35997289/147017080-7d6f40be-ebed-42c3-b770-d97d1a0c11cb.png)

2 - **Computer Hygiene**: Shows which computers within the domain are active with logins. It will present computers based on the Operating System version, with stale logins and passwords.
![image](https://user-images.githubusercontent.com/35997289/147017149-01717017-5b80-4326-a453-b9104e6fd2ae.png)

3 - **LAPS Deploy**: Local Administrative Password Solution (LAPS) Deploy tab shows how many computers have been configured by the LAPS solution. It will show which Operating Systems have LAPS deployed and the up-to-dateness vector on the LAPS Password.
![image](https://user-images.githubusercontent.com/35997289/147017248-9d10ee1b-603c-4ba8-8567-da5e5c550f0c.png)

4 - **LAPS Audit**: This tab shows which users retrieve the passwords for the local systems to use locally. LAPS Auditing helps unveil which user account has accessed the local administrator’s password of a given computer.
![image](https://user-images.githubusercontent.com/35997289/147017324-ac386684-34d4-4473-85ce-897f07d57ca6.png)

5 - **Non-Existent users activity**: This tab tracks the non-existent and potentially _sprayed_ accounts in your environment. These are accounts generating failed logins (4625s) in which the sub-status code references a non-existent account. (Note: these failed logins are distinct from existing accounts with incorrect passwords). You should look especially for machines hosting – or accounts exhibiting – a pattern of non-existent user types of failed logins. These can be early indicators of attack or attempted attack.
![image](https://user-images.githubusercontent.com/35997289/147017417-cd32ce2b-322b-4a91-bfa5-faa073066b88.png)

6 - **Group Changes**: This tab will show which Active Directory Groups have been changed. It will also show which users are making the most number of changes.
![image](https://user-images.githubusercontent.com/35997289/147017480-2e83b9bc-5597-4b18-b446-71fc4fbdd1b4.png)

7 - **User Authentication**: This tab will show which users are authenticating. It gives an overview of the authentication being performed by a specific user.
![image](https://user-images.githubusercontent.com/35997289/147017526-1dea44a0-1c93-433b-9a90-d07dceadf4a8.png)

8 - **SChannel**: This tab will show where SChannel authentication is occurring. It will show which computer that was initiating the Schannel authentication. You will need to temporarily install the MMA on the webserver or whatever server you suspect is using SSL or another deprecated encryption method. Then you will be able to see the actual cipher suite used and remediate the deprecated ones in use.
![image](https://user-images.githubusercontent.com/35997289/147017588-79c03c74-91f2-44f4-b56b-5eca2612849e.png)

9 - **Security Log Clear**: This tab shows where the security log has been cleared and by which user.
![image](https://user-images.githubusercontent.com/35997289/147017644-48f855b9-11ac-4f21-977c-c4c216f0d51c.png)

10 - **Audit Policy Changes**: This tab shows an attacker’s attempts to cover his tracks as he potentially has created environmental persistence
![image](https://user-images.githubusercontent.com/35997289/147017741-52b9ee10-18e8-41c6-bc17-82de52c59bb3.png)

11 - **User Management**: This tab shows the most common user management activities within the forest. User Management in a typical environment is relatively static and does not change much unless something is altered.
![image](https://user-images.githubusercontent.com/35997289/147017934-f636c739-9848-4ef4-b03f-e0f16bc951a1.png)

 
**Note**: Apart from this workbook, we recommend using the **Insecure Protocols** workbook of Microsoft Sentinel to identify their use and help to remove Insecure Protocols from your Active Directory and Azure Active Directory.

## Requirements
To be able to consume all scenarios described, it is necessary to meet the following requirements:
1. Have an enabled Azure Subscription with a **Microsoft Sentinel workspace**.
2. Create a new Group Policy Object to enable the necessary **audit policies** and **registry keys** in your Active Directory (applied to Domain Controllers).
3. Configure SACL for **Auditing LAPS**
4. Deploy a server as **Log Analytics Gateway**.
5. Configure the **Custom HTTP Data Collector API (PowerShell script)**.
6. **Connect** your Domain Controllers to Microsoft Sentinel throughout the Log Analytics Gateway (req. 4) by deploying the Microsoft Monitoring Agent.

## Deployment steps

### 1 - Advanced audit policies and registry keys configuration in Domain Controllers.

#### Advanced Audit Policies
To generate the necessary Security Events in the Domain Controllers it is needed to configure a new GPO (applied to Domain Controllers) to enable the following audit policies:

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
To generate the Events related with SChannel use, it is needed to configure the following registry key:
- **HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\EventLogging**
  - Change the value to **7**

### 2 - Audit LAPS password retrievals: Configure SACL
Make sure that proper audit settings (SACLs) are in place on the objects to audit. Follow next steps to audit LAPS password retrieval by configuring the audit settings at the root of the domain.
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
![image](https://user-images.githubusercontent.com/35997289/147013327-ac81e1bd-8f35-4f75-af5e-5c764700b397.png)


### 3 - Microsoft Sentinel: Configure AD integration and events collection
Once advanced audit policies and registry keys are configured, you need to configure the Microsoft Sentinel data sources.
#### Active Directory Integration
1. Go to your Microsoft Sentinel > Settings > Workspace Settings > Computer Groups > Active Directory and check the **Import active directory group memberships from computers**.
2. Click **Apply**.

![image](https://user-images.githubusercontent.com/35997289/147013407-29576bd2-476c-4a8e-aa15-0469691abcd4.png)

#### Events Collection
1. Go to your Microsoft Sentinel > Settings > Workspace Settings > Agents configuration
2. Click +Add windows event log and write **System**
3. Click on **Information** box to collect only the Information Events from System log and the apply.

![image](https://user-images.githubusercontent.com/35997289/147013426-5fa48d55-a39d-4283-bde2-5acaaba1bcc7.png)


#### SecurityEvents collection
To collect the SecurityEvents from Domain Controllers, there are two options when you use Microsoft Monitoring Agent and Sentinel:
- Use the Sentinel Data Connector **Security Events via Legacy Agent**.
- Enable Microsoft Defender for Cloud plans over Microsoft Sentinel workspace.
The difference between them resides in a billing way. Practically speaking, we need to collect Security Events, so there is no difference in the method chosen for this solution. We recommend you evaluate both options and choose the most interesting for you.
Below is the **Microsoft Defender for Cloud** method because it requires some additional (and simple) steps.

To enable **all Microsoft Defender for Cloud plans** in the Microsoft Sentinel workspace you need to:
1. Go to **Microsoft Defender for Cloud**.
2. Go to Environment Settings and expand your Tenant and Azure Subscriptions until find your Log Analytics Microsoft Sentinel workspace.
3. Click on your Microsoft Sentinel workspace.
4. Go to **Defender plans** and click on **Enable all Microsoft Defender for Cloudo plans**.
5. Click on **save**.
6. Go to **Data collection**.
7. Click on **All events** and **save**.

![image](https://user-images.githubusercontent.com/35997289/147013447-419879bf-c1ca-456a-897e-b1eb46f7e90e.png)

### 4 - Setup the Custom HTTP Data Collector API (PowerShell script) to populate Custom Logs.
The workbook need Active Directory Objects (users, computers, groups, etc) information to populate Hygiene and LAPS tabs. This information is collected by the custom data collector and uploaded to Microsoft Sentinel as Custom Logs format.
Follow the below steps to configure the Custom HTTP Data Collector:
1. Use the Log Analytics Gateway servers to run the Custom HTTP Data Collector.
2. Open an elevated PowerShell console and install the **RSAT AD DS Powershell module** by running the command:
<pre><code>Install-windowsfeature RSAT-AD-PowerShell</code></pre>
3. Fill and personalize the parameters section of the **ADObjectsToALA_v1.0.ps1** PS script. 
4. Fill the **domainlist.csv** according your environment. This file needs to have the headers line (dc,isLAPSDeployed) and one Domain Controller name and isLAPSDeployed value (comma separated) per line from each domain in scope as you can see in the following image.

![image](https://user-images.githubusercontent.com/35997289/147013878-80b68c94-1a30-4bb5-a8fb-dc1554e60104.png)

5. Create a scheduled task to run the PowerShell script **daily**.
6. To verify that the PowerShell script is running well, execute it manually and check if the Custom Logs are created in the Microsoft Sentinel workspace.
	Note: First you execute the script you probably need wait 5 to 10 minutes before seeing the logs in Microsoft Sentinel.
	
![image](https://user-images.githubusercontent.com/35997289/147014013-4444d9d8-888a-41f8-9f58-17242888a449.png)


### 5 - Create the Log Analytics Parser funtions in Microsoft Sentinel.
The workbook kusto queries refer many times to five Log Analytics Parser functions that need to be created or, on the contrary, the workbook will fail in different sections. These functions process the information received in Custom Logs format and calculate new fields based on raw data. Parser functions need to be created precisely with these names:
- VASWUsersParser
- VASWComputersParser
- VASWGroupParser
- VASWAdminAuditParser
- VASWPawAuditParser

![image](https://user-images.githubusercontent.com/35997289/147014420-2de4ee65-f3bb-4bb6-a8b3-b061956075ae.png)


### 6 - Connect Domain Controllers to Microsoft Sentinel.
To connect Domain Controllers to Microsoft Sentinel we use the Microsoft Monitoring Agent (MMA). Network communication between the MMA on Domain Contollers and Microsoft Sentinel is not direct. We use the Log Analytics Gateway as proxy for MMAs on DCs so, as you can see in the following image, the only server with network communication to the Microsoft Sentinel endpoints is the Log Analytics Gateway.

![image](https://user-images.githubusercontent.com/35997289/147012564-fc09a31d-aa45-4f66-be57-e5d6d7680a3b.png)

Necessary steps to deploy Log Analytics Gateway and Microsoft Monitoring Agents are:
#### Log Analytics Gateway server
1. Download and **Install** the Log Analytics Gateway software on the provided server. This software can be downloaded from the workspace: _Microsoft Sentinel > Settings > Workspace Settings > Agents management > Log Analytics Gateway_. The Log Analytics Gateway requires access to the four Microsoft Sentinel (Log Analytics) endpoints described [here](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/log-analytics-agent).
	- Note: In the Log Analytics Gateway installation wizard it is needed to configure the Log Analytics Gateway port. This port will be used when Microsoft Monitoring Agent is installed on **Domain Controllers**, in the proxy configuration step.

![image](https://user-images.githubusercontent.com/35997289/147014902-40c62a8e-3578-420b-837b-83d2d659f534.png)

2. Install the **Microsoft Monitoring Agent** and connect it to the Microsoft Sentinel with the WorkspaceId and PrimaryKey which are located in _Microsoft Sentinel > Settings > Workspace Settings > Agents management_.

#### Microsoft Monitoring Agents on each Domain Controller
1. Install the **Microsoft Monitoring Agent** and connect it to Microsoft Sentinel throught Log Analtyics Gateway server. Log Analytics Gateway need to be configured in the Proxy Setting tab with the port configured.

### 7 - Import the Visual Auditing Security Workbook
1. Go to Microsoft Sentinel > Workbooks.
2. Click on **Add workbook**.
3. Click on edit and go to **Advanced Editor**.
4. Remove the default workbook code and paste the code of **Visual Auditing Security Workbook.workbook**
5. Click **apply**.
6. Configure the workbook parameters:
	- Microsoft Sentinel workspace.
	- LAPSPasswordGUID (ms-mcs-AdmPwd). This parameter is only visible in the workbook edition mode. You need to enter the ms-mcs-AdmPwd GUID of your environment. It can be queried by running the following code:
    
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
The Visual Auditing Security Workbook was developed by **Diego Martínez Rellán (dmrellan) - Microsoft**. It was inspired by the Microsoft Support - Visual Auditing Security Toolkit (VAST) service (currently retired) developed originally by Brian Delaney and Jon Shectman.

## Acknowledgment
My special thanks to my coworker _**Alvaro Jiménez Contreras**_ for his help during this solution's evaluation development tasks and test phase.

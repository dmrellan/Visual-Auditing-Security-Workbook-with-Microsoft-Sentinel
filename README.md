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
![01 User Hygiene](https://user-images.githubusercontent.com/35997289/146858944-b030be17-4e0a-49b1-aea0-0a919b65edb9.jpg)

2 - **Computer Hygiene**: Shows which computers within the domain are active with logins. It will present computers based on the Operating System version, with stale logins and passwords.
![02 Computer Hygiene](https://user-images.githubusercontent.com/35997289/146858966-8c201466-78b7-422d-b3d6-27815f27c312.jpg)

3 - **LAPS Deploy**: Local Administrative Password Solution (LAPS) Deploy tab shows how many computers have been configured by the LAPS solution. It will show which Operating Systems have LAPS deployed and the up-to-dateness vector on the LAPS Password.
![03 LAPS Deploy](https://user-images.githubusercontent.com/35997289/146858975-d6794574-dc27-4c9d-a7b7-91cc137a9255.jpg)

4 - **LAPS Audit**: This tab shows which users retrieve the passwords for the local systems to use locally. LAPS Auditing helps unveil which user account has accessed the local administrator’s password of a given computer.
![04 LAPS Audit](https://user-images.githubusercontent.com/35997289/146859148-8e486ed9-cd0e-4aa3-8435-62fe216c39a9.jpg)

5 - **Non-Existent users activity**: This tab tracks the non-existent and potentially _sprayed_ accounts in your environment. These are accounts generating failed logins (4625s) in which the sub-status code references a non-existent account. (Note: these failed logins are distinct from existing accounts with incorrect passwords). You should look especially for machines hosting – or accounts exhibiting – a pattern of non-existent user types of failed logins. These can be early indicators of attack or attempted attack.
![05 Non-Existent users](https://user-images.githubusercontent.com/35997289/146858992-d0bbddd4-0373-4203-a8c2-7e2885cbc27a.jpg)

6 - **Group Changes**: This tab will show which Active Directory Groups have been changed. It will also show which users are making the most number of changes.
![06 Group Changes](https://user-images.githubusercontent.com/35997289/146858999-6e4c4bac-1024-4d2a-bf93-35815c0c1df1.jpg)

7 - **User Authentication**: This tab will show which users are authenticating. It gives an overview of the authentication being performed by a specific user.
![07 User Auth](https://user-images.githubusercontent.com/35997289/146859005-4afa0b4b-bbfe-4af6-838b-c96b3499fed9.jpg)

8 - **SChannel**: This tab will show where SChannel authentication is occurring. It will show which computer that was initiating the Schannel authentication. You will need to temporarily install the MMA on the webserver or whatever server you suspect is using SSL or another deprecated encryption method. Then you will be able to see the actual cipher suite used and remediate the deprecated ones in use.
![08 SChannel](https://user-images.githubusercontent.com/35997289/146859019-5de1c645-fcde-458c-9f03-ecc82eb272b6.jpg)

9 - **Security Log Clear**: This tab shows where the security log has been cleared and by which user.
![09 Security Log Clear](https://user-images.githubusercontent.com/35997289/146859028-8775c5b2-326d-443f-9787-987791ce38f3.jpg)

10 - **Audit Policy Changes**: This tab shows an attacker’s attempts to cover his tracks as he potentially has created environmental persistence
![10 Audit Policy Changes](https://user-images.githubusercontent.com/35997289/146859036-2ed68690-4756-4482-aeb8-d4a7e6ae02cc.jpg)

11 - **User Management**: This tab shows the most common user management activities within the forest. User Management in a typical environment is relatively static and does not change much unless something is altered.
![11 User Management](https://user-images.githubusercontent.com/35997289/146859040-6912a3be-5e9c-411d-8c86-38b3f2c36b67.jpg)

 
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
Special thanks to my co-worker Alvaro Jiménez Contreras for his help during the evaluation of this solution's development tasks and test phase.


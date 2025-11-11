# Visual Auditing Security Workbook with Microsoft Sentinel

> ⚠️ **‼️ UPDATE APRIL 2025 ‼️**  
> In March 2025, Azure changed the default table type when creating custom logs via the HTTP Data Collector API.  
> I’m currently working on updating the solution and will share a revised version as soon as possible.  
> **Until then, the deployment process WILL FAIL when attempting to send data.**

#### Update January 2024 - Azure Monitor Agent (AMA) supported

# Content
- [Overview](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#overview) 
- [Prerequisites](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#prerequisites)
- [Deployment steps](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#deployment-steps)
	- [1 - Advanced audit policies and registry keys configuration in Domain Controllers.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#1-advanced-audit-policies-and-registry-keys-configuration-in-domain-controllers)
	- [2 - Audit LAPS password retrievals: Configure SACL](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#2-audit-laps-password-retrievals-configure-sacl)
	- [3 - Data Collection Rules: Events and SecurityEvents](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#3-data-collection-rules-events-and-securityevents)
	- [4 - Setup the Custom HTTP Data Collector API (PowerShell script) to populate Custom Logs.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#4-setup-the-custom-http-data-collector-api-powershell-script-to-populate-custom-logs)
	- [5 - Create the Log Analytics Parser funtions in your Microsoft Sentinel.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#5-create-the-log-analytics-parser-funtions-in-microsoft-sentinel)
	- [6 - Connect your Domain Controllers to Microsoft Sentinel.](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#6-connect-domain-controllers-to-microsoft-sentinel)
	- [7 - Import the Visual Auditing Security Workbook](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#7-import-the-visual-auditing-security-workbook-with-ama)
- [Disclaimer](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#disclaimer)
- [Appendix with screenshots](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#appendix---screenshoots)
- [Author](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#author)
- [ChangeLog](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel?tab=readme-ov-file#changelog)

# Overview

The _Visual Auditing Security Workbook_ project comprises a collection of scenarios within an Azure Workbook tailored for Microsoft Sentinel. This workbook extracts pertinent information from your Active Directory Domain Controllers, empowering security teams to promptly discern insights regarding their Active Directory configuration, operations, and potential risks.

The workbook seamlessly visualizes data from two primary sources:
- **Security Events** from Domain Controllers and common **Events**.
- Active Directory users and computers account data submited by the **Custom HTTP Data Collector API**.

The existing Visual Auditing Security Workbook encompasses the following 11 scenarios ([Appendix with screenshots](https://github.com/dmrellan/Visual-Auditing-Security-with-Microsoft-Sentinel#Appendix---Screenshoots) at the end of this article):

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/87ea6449-dab6-4955-9465-2cdfdea03e6a)



1. **User Hygiene**: 
    - This scenario provides a comprehensive overview of the user population's status. It evaluates key aspects such as high-privilege users, individuals who have not logged in over an extended period, users with unchanged passwords for an extended duration, and those with the "Password Never Expired" setting enabled.
2. **Computer Hygiene**: 
    - This scenario offers a snapshot of active computers within the domain, categorized by their operating system versions. It identifies machines with stale logins and passwords, providing essential insights into the overall hygiene of your computing environment.
3. **LAPS Deploy**: 
    - The Local Administrative Password Solution (LAPS) Deploy tab reveals the number of computers configured with the LAPS solution. It specifies which operating systems have LAPS deployed and provides an up-to-dateness vector for the LAPS Password, ensuring that security teams can easily monitor and manage local administrator passwords.
4. **LAPS Audit**: 
    - In this tab, users can track who retrieves passwords for local systems for local use. LAPS Auditing exposes the user accounts that access local administrator passwords on specific computers, aiding in the identification of potential security risks.
5. **Non-Existent users activity**: 
    - This scenario monitors activities related to non-existent and potentially "sprayed" accounts in your environment. By identifying failed logins linked to non-existent accounts, security teams can recognize patterns indicative of an early attack or attempted intrusion.
6. **Group Changes**: 
    - The Group Changes tab highlights modifications made to Active Directory Groups, showcasing both the altered groups and the users responsible for the changes. This visibility aids in tracking and understanding group-related activities within the domain.
7. **User Authentication**: 
    - This tab provides insights into user authentication activities, offering an overview of the authentication processes performed by specific users. It enhances the understanding of user interactions with the system and helps identify any unusual authentication patterns.
8. **SChannel**: 
    - The SChannel tab reveals instances of SChannel authentication, specifying the initiating computer. By temporarily installing the Azure Monitor Agent on suspected servers, teams can analyze cipher suites and address any deprecated encryption methods in use.
9. **Security Log Clear**: 
    - This scenario identifies instances where the security log has been cleared and provides information on the user responsible. Detecting such events is crucial for maintaining the integrity of security logs and investigating potential security breaches.
10. **Audit Policy Changes**: 
    - The Audit Policy Changes tab reveals attempts by attackers to cover their tracks by potentially creating environmental persistence. This information is vital for identifying and mitigating security threats aimed at altering audit policies.
11. **User Management**:
    - This scenario focuses on the most common user management activities within the forest. By providing visibility into changes in user management, it aids in identifying any alterations to user accounts, ensuring the security of user access remains intact.


 
> **Note**: In addition to leveraging the *Visual Auditing Security Workbook*, we strongly recommend utilizing the **[Insecure Protocols](https://techcommunity.microsoft.com/t5/microsoft-sentinel-blog/azure-sentinel-insecure-protocols-workbook-reimagined/ba-p/1558375)** workbook within Microsoft Sentinel. This supplementary tool is instrumental in identifying the presence of insecure protocols and plays a crucial role in eliminating them from both your Active Directory and Azure Active Directory environments. By incorporating insights from the *Insecure Protocols* workbook, your security team can further enhance the overall resilience of your systems and fortify them against potential vulnerabilities associated with insecure communication protocols.

# Prerequisites

Before implementing the Visual Auditing Security Workbook and its associated scenarios, ensure that you meet the following prerequisites to guarantee a seamless setup and effective utilization:

1. **Azure Subscription**: Ensure you have an active Azure Subscription with a provisioned **Microsoft Sentinel workspace**.

2. **Group Policy Object (GPO)**: 
   - Create a new GPO to enable the necessary **audit policies** and **registry keys** in your Active Directory.
   - Apply this GPO to your Domain Controllers to enforce the required security configurations.

3. **Security Auditing Configuration for LAPS (Local Administrative Password Solution)**: 
   - Set up Security Auditing Configuration Lists (SACL) to enable auditing for LAPS activities.

4. **Custom HTTP Data Collector API Configuration**: 
   - Configure the **Custom HTTP Data Collector API (PowerShell script)** to collect and submit Active Directory users and computers account data.

5. **Azure Monitor Agent Deployment**: 
   - Connect your Domain Controllers to Microsoft Sentinel by deploying the **Azure Monitor Agent**.
   - This agent facilitates the collection of relevant data for analysis.

6. **Data Collection Rules**: 
   - Create two [**Data Collection Rules**](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview?tabs=portal) to collect specific event data (_Events_ and _SecurityEvents_) based on XPath queries.
   - Associate these rules with your Domain Controllers to capture essential information for the scenarios.


# Deployment steps

## 1. Advanced Audit Policies and Registry Keys Configuration in Domain Controllers

### Advanced Audit Policies
To generate the necessary Security Events on Domain Controllers, configure a new Group Policy Object (GPO) applied to Domain Controllers to enable the following audit policies:
- **Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies:**

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


![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/e3dfb934-1956-4bff-b331-c630bb6fc260)


### Registry Keys

To generate Events related to SChannel use, configure the following registry key:

- **HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\EventLogging**
  - Change the value to **7**
 
![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/18aa53e1-8ead-458b-9155-f090617edd0e)

To enable logging of unsecure LDAP binds:
- **HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\16 LDAP Interface Events**
  - Change the value to **2**

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/ee411b4e-dc4d-452f-a065-6d4a0a919c6e)
![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/117a928a-6382-4b25-ab80-3d4ecf4bda14)



## 2. Audit LAPS Password Retrievals: Configure SACL

Ensure proper audit settings (SACLs) are in place on objects to audit. Follow these steps to audit LAPS password retrieval by configuring audit settings at the root of the domain:

1. Open **Active Directory Users and Computers**.
2. Enable **View\Advanced Features**.
3. Select root of the domain.
4. Open **Properties** and go to the **Security** tab.

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/cf262e83-33b6-4a3d-b6b2-23f44b529b52)

5. Click the **Advanced** button and go to **Auditing** tab.

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/33902acb-1b66-48f0-85a1-8776a95f165a)

6. Click **Add** to add a new entry.
7. Change the Principal to **Eveyone**, type to **Success**, Applies to **Descendant Computer objects**.

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/84eaf05c-0b32-4c33-b755-b3f9bcc351f3)

8. Click **Clear all** at the bottom to uncheck all the prechecked items.

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/3d57e5da-f0d6-4399-b347-1c223feb6aaf)

9. Check the box **All extended rights**.

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/c91c3ea4-acbe-41e7-81c3-1be7f2f7bfd3)

10. Check the box **Read ms-Mcs-AdmPwd**.

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/1f428ee7-175e-40c3-b46d-0f3e685cb0ab)

11. Click **OK** and close all security properties.

![image](https://user-images.githubusercontent.com/35997289/147013327-ac81e1bd-8f35-4f75-af5e-5c764700b397.png)

## 3. Data Collection Rules: Events and SecurityEvents

After configuring advanced audit policies and registry keys, configure the Data Collection Rules.

### DCR to collect 'Events'

1. Go to Azure Portal > Monitor > Data Collection Rules and click on **+ Create**.
2. Follow the wizard and fill the gaps with the following values:
    - Rule Name: dcr-VASW-Sentinel-Events-001 (or other which fits with your naming convention)
    - Subscription: _your subscription_
    - Resource Group: _your resource group_
    - Region: _your region where the dcr is deployed_
    - Platform type: Windows
3. Click **Next** and go to the _Resources_ tab. Leave the resources blank (we're only creating the DCR in this step).
4. Click **Next** and go to the _Collect and deliver_ tab. Click on **+ Add data source**.
5. Create a new **Windows Event Log** data source by using the below custom xPath queries:
    > - System!*[System[(EventID=36880)]]
    > - Microsoft-Windows-SMBServer/Audit!*[System[EventID=3000]]
    > - Directory Service!*[System[(EventID=2889)]]
    > - System!*[System[(EventID=5827) or (EventID=5829) or (EventID=5828) or (EventID=5830) or (EventID=5831)]]
    > - Application!*[System[(EventID=1900) or (EventID=19191) or (EventID=1919) or (EventID=19201) or (EventID=1920) or (EventID=1921) or (EventID=19211) or (EventID=1922) or (EventID=1923)]]

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/39c197b2-8517-4343-8f71-902c803cb00a)

6. Select your Sentinel workspace as **destination**.
7. Add the necessary **tags** based on your tag policy and finish the wizard.

### DCR to collect 'SecurityEvents'

1. Go to Azure Portal > Sentinel.
2. Install the **Windows Security Events via AMA** data connector from **Content Hub**
3. Go to Data connectors to configure the **Windows Security Events via AMA** data connector with the following Data Collection Rule:
    - Rule Name: dcr-VASW-Sentinel-SecurityEvents-001 (or other which fits with your naming convention)
    - Subscription: _your subscription_
    - Resource Group: _your resource group_
4. Create a new **DCR** by using the below custom xPath queries:
    > - Security!*[System[(EventID=1102) or (EventID=4624) or (EventID=4625) or (EventID=4719) or (EventID=4720) or (EventID=4722) or (EventID=4724) or (EventID=4725) or (EventID=4726) or (EventID=4728) or (EventID=4729) or (EventID=4732) or (EventID=4733) or (EventID=4740) or (EventID=4756)]]
    > - Security!*[System[(EventID=4757) or (EventID=4765) or (EventID=4766) or (EventID=4768) or (EventID=4769) or (EventID=4771) or (EventID=4776) or (EventID=4794)]]
    > - Security!*[System[EventID=4662]] and (*[EventData[Data[@Name='SubjectUserSid'] !='S-1-5-18']] and *[EventData[Data[@Name='ObjectType'] ='%{bf967a86-0de6-11d0-a285-00aa003049e2}']])

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/e89277db-d008-463d-9c92-1798032fce8d)

5. Review and create the DCR.

## 4. Setup the Custom HTTP Data Collector API (PowerShell script) to populate Custom Logs.

The workbook requires Active Directory Objects (users, computers, groups, etc.) information to populate Hygiene and LAPS tabs. This information is collected by the custom data collector and uploaded to Microsoft Sentinel as Custom Logs.
Follow these steps to configure the Custom HTTP Data Collector:

1. Use one Domain Controller or another server to run the Custom HTTP Data Collector.
2. Open an elevated PowerShell console and install the **RSAT AD DS Powershell module** by running the command:
<pre><code>Install-windowsfeature RSAT-AD-PowerShell</code></pre>
3. Create the new **VASWDataToSentinel** event log source by executing the following command:
<pre><code>New-EventLog –LogName Application –Source "VASWDataToSentinel"</code></pre>
4. Fill and personalize the parameters section of the **ADObjectsToALA.ps1** PS script.
5. Fill the **domainlist.csv** according your environment. This file needs to have the headers line (dc,isLAPSDeployed) and one Domain Controller name and isLAPSDeployed value (comma separated) per line from each domain in scope as you can see in the following image.

![image](https://user-images.githubusercontent.com/35997289/147013878-80b68c94-1a30-4bb5-a8fb-dc1554e60104.png)

6. Create a scheduled task to run the PowerShell script **daily**.
7. To verify that the PowerShell script is running successfully and Custom Logs are created in the Microsoft Sentinel workspace:
  1. Execute the PowerShell script manually to observe any errors or unexpected behavior.
  2. Check the Microsoft Sentinel workspace for the presence of Custom Logs. The **type** of these tables MUST BE **"Custom table (classic)"**

   **Note:** During the initial script execution, allow 5 to 10 minutes for the logs to appear in Microsoft Sentinel.

![image](https://user-images.githubusercontent.com/35997289/147014013-4444d9d8-888a-41f8-9f58-17242888a449.png)


## 5. Create the Log Analytics Parser funtions in Microsoft Sentinel.

The workbook relies on five Log Analytics Parser functions that must be created to process information from Custom Logs and calculate new fields based on raw data. Ensure that these functions are created with the following names:

- VASWUsersParser
- VASWComputersParser
- VASWGroupParser
- VASWAdminAuditParser
- VASWPawAuditParser

Note: In "**Legacy category**" field you can use "VASWFunctions" value for all functions.

![image](https://user-images.githubusercontent.com/35997289/147014420-2de4ee65-f3bb-4bb6-a8b3-b061956075ae.png)

## 6. Connect Domain Controllers to Microsoft Sentinel.
In most situations, your Domain Controllers will be located outside of Azure (on-premises). If this is the case, before enabling the [Azure Monitor Agent (AMA)](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-manage?tabs=azure-portal), you will need to deploy [Azure ARC](https://learn.microsoft.com/en-us/azure/azure-arc/servers/plan-at-scale-deployment) to connect your Domain Controllers to Azure, and then enable the AMA extension.

![image](https://github.com/dmrellan/Visual-Auditing-Security-Workbook-with-Microsoft-Sentinel/assets/35997289/85e5e4f2-c6f6-4587-a22c-c405bfce483b)

## 7. Import the "Visual Auditing Security Workbook with AMA"
1. Go to Microsoft Sentinel > Workbooks.
2. Click on **Add workbook**.
3. Click on edit and go to **Advanced Editor**.
4. Remove the default workbook code and paste the code of **Visual Auditing Security Workbook with AMA.workbook**
5. Click **apply**.
6. Configure the workbook **parameters and hide parameters**:
	- Azure Subscription: Hidden parameter, only visible in the workbook edition mode. The subscription where you have your Microsoft Sentinel workspace.
	- Microsoft Sentinel workspace.
	- LAPSPasswordGUID (ms-mcs-AdmPwd): Hidden parameter. You need to enter the ms-mcs-AdmPwd GUID of your environment. It can be queried by running the following code:
    
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

### _**Disclaimer**_

_**This sample workbook is not supported under any Microsoft standard support program or service. This sample workbook and scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.**_


## Appendix - Screenshoots
![image](https://user-images.githubusercontent.com/35997289/147017080-7d6f40be-ebed-42c3-b770-d97d1a0c11cb.png)
![image](https://user-images.githubusercontent.com/35997289/147017149-01717017-5b80-4326-a453-b9104e6fd2ae.png)
![image](https://user-images.githubusercontent.com/35997289/147017248-9d10ee1b-603c-4ba8-8567-da5e5c550f0c.png)
![image](https://user-images.githubusercontent.com/35997289/147017324-ac386684-34d4-4473-85ce-897f07d57ca6.png)
![image](https://user-images.githubusercontent.com/35997289/147017417-cd32ce2b-322b-4a91-bfa5-faa073066b88.png)
![image](https://user-images.githubusercontent.com/35997289/147017480-2e83b9bc-5597-4b18-b446-71fc4fbdd1b4.png)
![image](https://user-images.githubusercontent.com/35997289/147017526-1dea44a0-1c93-433b-9a90-d07dceadf4a8.png)
![image](https://user-images.githubusercontent.com/35997289/147017588-79c03c74-91f2-44f4-b56b-5eca2612849e.png)
![image](https://user-images.githubusercontent.com/35997289/147017644-48f855b9-11ac-4f21-977c-c4c216f0d51c.png)
![image](https://user-images.githubusercontent.com/35997289/147017741-52b9ee10-18e8-41c6-bc17-82de52c59bb3.png)
![image](https://user-images.githubusercontent.com/35997289/147017934-f636c739-9848-4ef4-b03f-e0f16bc951a1.png)

## Author
The Visual Auditing Security Workbook was developed by **Diego Martínez Rellán (dmrellan) - Microsoft**. It draws inspiration from the Microsoft Support - Visual Auditing Security Toolkit (VAST) service, originally created by Brian Delaney and Jon Shectman (currently retired).



## ChangeLog
### Version 1.5 (January 2024)
- **Solution Modifications**
  - The solution has been adapted to run with AMA (Azure Monitor Agent).
- **Visual Auditing Security Workbook Enhancements**
  - User Hygiene:
    - Introduces a new gMSA filter.
    - Includes new gMSA columns in the Details table.
  - Introduces a new method to identify Domain Controllers with AMA, as Active Directory Integration is no longer supported with AMA.
  - Removed the "DCsGroup Display Name" element.
  - Various minor improvements and fixes implemented.
  - **Audit Policy Tab:**
    - Added the isComputer filter for enhanced filtering.
- **Custom HTTP Data Collector API enhancements**
  - Paged groups submissions have been implemented.
  - Enhanced EventLogging for improved functionality.
  - Added a section for gMSAs (Group Managed Service Accounts).
- **Log Analytics Parser Functions**
  - VASWUserParser.kusto: Added gMSA information and improved treatment of the msDSPrincipalName field.

### Version 1.4 (June 27th, 2022)
- **Visual Auditing Security Workbook**
  - Workbook version: 1.4.
  - New workbook global parameter: "DCsGroup Display Name" (to support different languages).
  - LAPS Deployment:
	  - New "Total count" column to "Total computers by OS and LAPS Deployed" table.
	  - Minor improvements.
  - LAPS Audit: New table "Updated and outdated computers" added.
  - Audit Policy tab: New filter "isComputer".
  - Authentication tab:
	  - New table: "Top 10 Status messages".
	  - New Table: "Total auth events by source (Top 10). Filtered by X account".
	  - Display names added to the EventID dropdown filter.
	  - Minor improvements in the Details table.
	  - Fixed parser logic KQL queries in all tables.
  - Group changes tab:
	  - Added a new column "Total changes" to the change-makers table. The table ordered by this new column.
  - Nonexistent users tab: Visualization improvements.
  - Other minor improvements.
- **Custom HTTP Data Collector API**
  - No modifications. You can continue using _ADObjectsToALA_v1.1.ps1_
- **Log Analytics Parser Functions**
  - No modifications.

### Version 1.1 (March 9th, 2022)
- **Custom HTTP Data Collector API**
  - Fixed typos in the Powershell script.
  - Improved logging.
  - The maximum number of elements by post is 10k.
- **Log Analytics Parser Functions**
  - VASWComputersParser.kusto: Fixed an issue when LAPS is not deployed.

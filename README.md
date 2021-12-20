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
#### Events Collection
#### Microsoft Defender for Cloud

### 4 - Connect your Domain Controllers to Microsoft Sentinel
### 5 - Setup the PowerShell script to populate Custom Logs
### 6 - Create the Log Analytics Parser Funtions in your Microsoft Sentinel
### 7 - Import the Visual Auditing Security Workbook

## Author
The Visual Auditing Security Workbook was developed by **Diego Martínez Rellán (dmrellan) - Microsoft**. It is inspired by the Visual Auditing Security Toolkit (VAST) service from Microsoft Support (currently retired) developed by Brian Delaney and Jon Shectman.

## Acknowledgment
Special thanks to my co-worker Alvaro Jiménez Contreras for his help during the evaluation of this solution's development tasks and test phase.


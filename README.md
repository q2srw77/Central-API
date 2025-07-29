## Central API Tool

This menu driven Central API Powershell Script is designed to get your Token and store it securely locally on your system. 

Then you can use the Endpoint Search, Tenant Search or Endpoint Migration

**For Endpoint & Tenant Search** - You can enter the full or partial name. It will find all Endpoints/Tenants that match.

*If Endpoint Search gets an error about too many requests, you will need to modify the Start-Sleep for the Function: Get-SOPHOSPartnerEndpointsAllTenants*

## Download
Click on the Green <>Code button and click on Download Zip

## Execution
Requires PowerShell 5.1 or higher.

Run PowerShell (Do Not Run as an Admin)

Execute the following command to allow the unsigned script for this process

**Set-ExecutionPolicy unrestricted -Scope Process**

Then execute the **./Sophos Central API Tool.ps1**

# Endpoint Migration

The Endpoint Migration will move the Endpoint ID from the Current Tenant to the Destination Tenant.

Endpoint ID, Current Tenant ID, and Destination Tenant ID are all required before you start.

- Endpoint Search can get the Endpoint ID and Current Tenant ID. 
- Tenant Search can get the Destination ID.
- 
- To move multiple Endpoints, add them all to the Endpoint ID Input seperated by a comma.
- Example: EndpointID,EndpointID,EndpointID

# Migration Status

Migration Status can be used after the migration job has been sent to confirm it completed successfully. This only check the last migration jon that was run.

# Block SHA256 Hash on all Tenants

This will go through all Sophos Central Tenants and add the SHA256 to the Blocked Items under Global Settings

-Enter the SHA256 that you want to block
-Enter the Comment for the Blocked Item.

The Sleep Timer might need to be adjusted for larger tenant lists.

# Firewall List Export to CSV

This will go through all Sophos Central Tenants to collect the Firewall data and export it to a CSV file.

-Firewall Name, Model, Firmware Version and Customer Name are exported
-The FirewallList.csv will be created in the directory that the PowerShell was executed from.

# Extended Support OS Export to CSV

This will go through all Sophos Central Tenants to collect the Extended Support OS Computers and export it to a CSV file.

-Computer Name, OS, and Customer Name are exported
-The ExtendedSupportList.csv will be created in the directory that the PowerShell was executed from.


```
This script isn't supported by Sophos Support
```

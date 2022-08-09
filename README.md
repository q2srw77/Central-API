## Central API Tool

This menu driven Central API Powershell Script is designed to get your Token and store it securely locally on your system. 

Then you can use the Endpoint Search, Tenant Search or Endpoint Migration

**For Endpoint & Tenant Search** - You can enter the full or partial name. It will find all Endpoints/Tenants that match.

```
If Endpoint Search gets an error about too many requests, you will need to modify the Start-Sleep for the Function: Get-SOPHOSPartnerEndpointsAllTenants ***
```  

# Endpoint Migration

The Endpoint Migration will move the Endpoint ID from the Current Tenant to the Destination Tenant.

Endpoint ID, Current Tenant ID, and Destination Tenant ID are all required before you start.

- Endpoint Search can get the Endpoint ID and Current Tenant ID. 
- Tenant Search can get the Destination ID.

# Migration Status

Migration Status can be used after the migration job has been sent to confirm it completed successfully
  
```
This script isn't supported by Sophos Support
```

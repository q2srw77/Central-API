#Sophos Central API Delete Endpoints in a Group

#***Can be used as a nightly script to clear Pooled VDI Desktops from Sophos Central to avoid duplicates***


#Enter the Central Partner API Credentials

$ClientID_Creds = "<Central Partner API Client ID Here>"

$ClientSecret_Creds = "<Central Partner API Client Secret>"


#Enter the Tenant ID  ***You can use the Central API Tool to find this***

$customerid = "<Tenant ID here>"

#Enter the Group Name to search for

$groupName = "<Group Name>"


function Get-SOPHOSToken{
    
   	# SOPHOS OAuth URL
	$TokenURI = "https://id.sophos.com/api/v2/oauth2/token"
	
	# TokenRequestBody for oAuth2
    $TokenRequestBody = @{
        "grant_type" = "client_credentials";
        "client_id" = $ClientID_Creds;
        "client_secret" = $ClientSecret_Creds;
        "scope" = "token";
    }
    $TokenRequestHeaders = @{
        "content-type" = "application/x-www-form-urlencoded";
    }
	
    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# Post Request to SOPHOS OAuth2 token:
	$APIAuthResult = (Invoke-RestMethod -Method Post -Uri $TokenURI -Body $TokenRequestBody -Headers $TokenRequestHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)

	# If there's an error requesting the token, say so, display the error, and break:
    if ($Error) {
        Write-Output "FAILED - Unable to retreive SOPHOS API Authentication Token - $($Error)"
        Break
	}

    # Set the Token as Global for use later on:
    $Global:TokenExpiration = (Get-Date).AddSeconds($APIAuthResult.expires_in)
    $Global:Token = $APIAuthResult.access_token

    # Get the Partner ID Also
    Get-SOPHOSPartnerID
}


function Get-SOPHOSPartnerID{

	# SOPHOS Whoami URI:
	$WhoamiURI = "https://api.central.sophos.com/whoami/v1"
	
    # SOPHOS Whoami Headers:
    $WhoamiRequestHeaders = @{
        "Content-Type" = "application/json";
        "Authorization" = "Bearer $Global:Token";
    }
	
    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# Post Request to SOPHOS for Whoami Details:
	$APIWhoamiResult = (Invoke-RestMethod -Method Get -Uri $WhoamiURI -Headers $WhoamiRequestHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
    
    # Set the PartnerID and ApiHost as Global for use later on:
    $global:ApiPartnerId = $APIWhoamiResult.id
    $global:ApiHost = $APIWhoamiResult.apiHosts.global

}


#Delete Endpoints in a Group ***This will delete all devices in any group name that matches***

function deleteEndpoints{
# Set TLS Version
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			
# SOPHOS Whoami Headers
	$PartnerTenantHeaders = @{
		"Authorization" = "Bearer $global:Token";
		"X-Partner-ID" = "$global:ApiPartnerId";
   }

#Set Tenant Info
    $tenant = (Invoke-RestMethod -Method Get -URI "https://api.central.sophos.com/partner/v1/tenants/$customerid" -Headers $PartnerTenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
    $apihost = $tenant.apiHost
    $tenantid = $tenant.id
    $tenantname = $tenant.name

# SOPHOS Customer Tenant API Headers:
    $TentantAPIHeaders = @{
        "Authorization" = "Bearer $global:Token";
        "X-Tenant-ID" = "$tenantid";
       }
		
# Post Request to SOPHOS for Endpoint API:
    $GroupEndpointResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints?pageSize=500&search="$groupName"&searchFields=groupName" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
	
# Display the Results
        
    foreach ($id in $GroupEndpointResult.items) {
        $endpointID = $id.id
        Invoke-RestMethod -Method Delete -Uri $apiHost"/endpoint/v1/endpoints/$endpointID" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error  
        }
    #break
    }


Get-SOPHOSToken
deleteEndpoints
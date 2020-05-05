#Sophos Central API Powershell Command Line Menu

function Get-SOPHOSToken{

    # See if Config file has been setup, if it doesn't exists then run the Set-SOPHOSCredentials Function
    if ((Test-Path c:\SophosCentral\sophos_partner_secureaccess.json) -eq $false){
        Set-SOPHOSCredentials
        }
    
    # Read JSON Config File
    $credentials = Get-Content c:\SophosCentral\sophos_partner_secureaccess.json | ConvertFrom-Json
    $clientId = $credentials[0]
    $clientSecret = $credentials[1] | ConvertTo-SecureString

    # Create PSCredential Object for Credentials
    $SecureCredentials = New-Object System.Management.Automation.PSCredential -ArgumentList $clientId , $clientSecret
    
	# SOPHOS OAuth URL
	$TokenURI = "https://id.sophos.com/api/v2/oauth2/token"
	
	# TokenRequestBody for oAuth2
    $TokenRequestBody = @{
        "grant_type" = "client_credentials";
        "client_id" = $SecureCredentials.GetNetworkCredential().Username;
        "client_secret" = $SecureCredentials.GetNetworkCredential().Password;
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


function Set-SOPHOSCredentials{
    # Prompt for Credentials
    $clientId = Read-Host "Please Enter your Client ID"
    $clientSecret = Read-Host "Please Enter your Client Secret" -AsSecureString | ConvertFrom-SecureString

    # Out to JSON Config File
    ConvertTo-Json $ClientID, $ClientSecret | Out-File c:\SophosCentral\sophos_partner_secureaccess.json -Force

    # Run the Get-SOPHOSToken Function to get the API Key
    Get-SOPHOSToken

}


function Get-SOPHOSTokenExpiry{
    # Compare the TokenExpiry Date to Now and re-generate if needed
    if ((Get-Date) -ge ($global:TokenExpiry)){
        Get-SOPHOSToken
    }
}


function Get-SOPHOSPartnerEndpointsAllTenants{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Get the latest list of partners with the ID, API Host and Name
    Get-SOPHOSPartnerTenants

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Set Partner Tenant URI
            $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants"

    
    foreach ($tenant in $global:PartnerTenants) {
        
        $apihost = $tenant.apiHost
        $tenantid = $tenant.id

        # SOPHOS Customer Tenant API Headers:
        $TentantAPIHeaders = @{
            "Authorization" = "Bearer $global:Token";
            "X-Tenant-ID" = "$tenantid";
        }
        if ($apihost -ne $null){
	        # Post Request to SOPHOS for Endpoint API:
	        $AllTenantEndpointResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
        }
        # All results for debugging
        # Write-Host($TenantEndpointResult.items | Out-GridView)

        # Build the query
        $EndpointTenantSearch = $AllTenantEndpointResult.items | ? {($_.hostname -match $computername)}
        if ($EndpointTenantSearch.hostname -eq $computername) {
        $EndpointTenantID = $EndpointTenantSearch
        }
        
        }

        #Build Search Output
        if ($EndpointTenantID.hostname -eq $computername) {
            $TenantID = ($EndpointTenantID.tenant -replace ‘[@{id=}]’)
            Write-host "Computer Name: $computername"
            Write-Host "Tenant: $TenantID"
            
            # SOPHOS Whoami Headers
            $PartnerTenantHeaders = @{
            "Authorization" = "Bearer $global:Token";
            "X-Partner-ID" = "$global:ApiPartnerId";
            }

            #Tenant Name Results
            $PartnerTenantResult = (Invoke-RestMethod -Method Get -Uri $PartnerTenantURI -Headers $PartnerTenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
            $TenantName = $PartnerTenantResult.items | ? {($_.id -match "$TenantID")}
            write-host "Tenant Name: $TenantName"
        }
        else {
        Write-Host "Computer not found" }
}


function Show-Menu {
    param (
        [string]$Title = 'Sophos Central API Access'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host ""
    Write-Host "1: Get Sophos Central API Token"
    Write-Host "2: Search for Endpoint"
    Write-Host "Q: Press 'Q' to quit."
}

do
 {
    Show-Menu
    Write-Host ""
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    '1' {
    Set-SOPHOSCredentials
    } '2' {
    $computername = Read-Host -Prompt 'Enter the Computer Name your looking for'
    Get-SOPHOSPartnerEndpointsAllTenants -hostname $computername
    }
    }
    pause
 }
 until ($selection -eq 'q')
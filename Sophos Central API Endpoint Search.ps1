#Sophos Central API Powershell Command Line Menu

function Get-SOPHOSToken{

    # See if Config file has been setup, if it doesn't exists then run the Set-SOPHOSCredentials Function
    if ((Test-Path $env:userprofile\sophos_partner_secureaccess.json) -eq $false){
        Set-SOPHOSCredentials
        }
    
    # Read JSON Config File
    $credentials = Get-Content $env:userprofile\sophos_partner_secureaccess.json | ConvertFrom-Json
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
    # Prompt for Credentials
    Write-host ""
    Write-host "***********************"
    Write-host ""
    Write-host "Set your Sophos Central API Credentials"
    Write-host ""
	$clientId = Read-Host "Please Enter your Client ID"
    $clientSecret = Read-Host "Please Enter your Client Secret" -AsSecureString | ConvertFrom-SecureString

    # Out to JSON Config File
    ConvertTo-Json $ClientID, $ClientSecret | Out-File $env:userprofile\sophos_partner_secureaccess.json -Force
	Write-host ""
    Write-host "***********************"
    Write-host ""
    Write-host "Credentials stored securely" -ForegroundColor Green
    Write-host ""
    Write-host "***********************"
    pause
    # Run the Get-SOPHOSToken Function to get the API Key
    Get-SOPHOSToken

}


function Get-SOPHOSTokenExpiry{
    # Compare the TokenExpiry Date to Now and re-generate if needed
    if ((Get-Date) -ge ($global:TokenExpiry)){
        Get-SOPHOSToken
    }
}

function Get-SOPHOSPartnerTenants{

    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry

	# SOPHOS Whoami URI
	$PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants?pageTotal=True"
	
    # SOPHOS Whoami Headers
    $PartnerTenantHeaders = @{
        "Authorization" = "Bearer $global:Token";
        "X-Partner-ID" = "$global:ApiPartnerId";
    }

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# Post Request to SOPHOS Endpoint Gateway, This request is just used to get the pages (waste of a request I know)
	$PartnerTenantResult = (Invoke-RestMethod -Method Get -Uri $PartnerTenantURI -Headers $PartnerTenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
    
    # Check them all into this collection
    $AllPartnerTenantResults = @()
    
    For ($i=1; $i -le $PartnerTenantResult.pages.total; $i++) {
        $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants?pageTotal=True&page=$i"
        $AllPartnerTenantResults += (Invoke-RestMethod -Method Get -Uri $PartnerTenantURI -Headers $PartnerTenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
    }

    $global:PartnerTenants = $AllPartnerTenantResults.items | Select -Property id, name, apiHost

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
        $tenantname = $tenant.name

         # SOPHOS Customer Tenant API Headers:
		 
        $TentantAPIHeaders = @{
            "Authorization" = "Bearer $global:Token";
            "X-Tenant-ID" = "$tenantid";
        }
        if ($apihost -ne $null){
	        # Post Request to SOPHOS for Endpoint API:
	        $AllTenantEndpointResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
        }

        # Build the query
        $EndpointTenantSearch = $AllTenantEndpointResult.items | ? {($_.hostname -like "*$computername*")}
        
        if ($EndpointTenantSearch.hostname -like "*$computername*") {
            # This should speed up the script and fix the problem.
            # This removes the need for the next conditional statement.
            # If the computer is found, it uses the $tenantname and $tenantid variable within the existing loop
            # If more tenant information is needed add the additional items on line 126 from the intial partner list
            # The break statement kills the loop.
            foreach ($hostname in $EndpointTenantSearch) {
            $computer = $hostname.hostname
            $tamperprotection = $hostname.tamperProtectionEnabled
            $person = $hostname.associatedPerson | Select-Object -ExpandProperty viaLogin
            Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "Computer Name: $computer"  -ForegroundColor Green
			Write-host ""
            Write-host "User: $person"  -ForegroundColor Green
            Write-host ""
			Write-host "TenantName: $TenantName"  -ForegroundColor Green
			Write-host ""
			Write-host "Tamper Protection Enabled: $tamperprotection" -ForegroundColor Green
            Write-host ""
            # Write-host "TenantID: $TenantID" -ForegroundColor Green
            Write-host "***********************"
            }
			#Write-host "0xBennyV was here 2020"
            #break
        }
        Else {
            Write-host ""
			Write-host "***********************"
            Write-host "Tenant Name: $TenantName" -ForegroundColor Red
            Write-host "Computer Not Found" -ForegroundColor Red
            Write-host "***********************"
            }
            
        
    }


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
	Write-Host "3: Delete Token"
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
    Write-host ""
	$computername = Read-Host -Prompt 'Enter the Full or Partial Computer Name your looking for'
    Get-SOPHOSPartnerEndpointsAllTenants -hostname $computername
    } '3' {
	 if ((Test-Path $env:userprofile\sophos_partner_secureaccess.json) -eq $true){
        Remove-item $env:userprofile\sophos_partner_secureaccess.json
		Write-host ""
		Write-host "***Sophos Central Token Deleted***" -foregroundcolor Green
		Write-host ""
        }
	}
    }
    pause
 }
 until ($selection -eq 'q')

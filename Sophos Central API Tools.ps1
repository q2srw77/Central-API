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
        Start-Sleep -Seconds 5
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
	        $AllTenantEndpointResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints?pageSize=500&type=computer&lastSeenBefore=P1D" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
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
            $id = $hostname.id
            $tamperprotection = $hostname.tamperProtectionEnabled
            $person = $hostname.associatedPerson | Select-Object -ExpandProperty viaLogin
            $tpallinfo = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints/"$id"/tamper-protection" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
            $tppassword = $tpallinfo.password
            $tpprevpass = $tpallinfo.previousPasswords
            Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "Computer Name: $computer"  -ForegroundColor Green
			Write-host ""
            Write-host "Computer ID: $id"  -ForegroundColor Green
            Write-host ""
            Write-host "User: $person"  -ForegroundColor Green
            Write-host ""
			Write-host "TenantName: $TenantName"  -ForegroundColor Green
			Write-host ""
            Write-host "TenantID: $Tenantid"  -ForegroundColor Green
			Write-host ""
			Write-host "Tamper Protection Enabled: $tamperprotection" -ForegroundColor Green
            Write-host ""
            Write-host "Tamper Protection Password: $tppassword" -ForegroundColor Green
            Write-host ""
            Write-host "Tamper Protection Previous Passwords: $tpprevpass" -ForegroundColor Green
            Write-host ""
            Write-host "***********************"
            }
			#Write-host "0xBennyV was here 2020"
            #break
        }
        
        
    }


}

function Get-SOPHOSPartnerTenantSearch{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Get the latest list of partners with the ID, API Host and Name
    Get-SOPHOSPartnerTenants

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Set Partner Tenant URI
            $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants"

	$TenantSearch = $global:PartnerTenants | ? {($_.name -like "*$companyname*")}
    		
        foreach ($name in $TenantSearch) {
            $cname = $name.name
			$id = $name.id
            Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "Tenant Name: $cname"  -ForegroundColor Green
			Write-host ""
            Write-host "Tenant ID: $id"  -ForegroundColor Green
            Write-host ""
            Write-host "***********************"
            }
             
        
    }

function Get-EndpointMigration{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Get the latest list of partners with the ID, API Host and Name
    Get-SOPHOSPartnerTenants

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Set Partner Tenant URI
            $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants"

    #Set Tenant Names

        $DestTenantSearch = $global:PartnerTenants | ? {($_.id -like "*$desttenant*")}
        $FromTenantSearch = $global:PartnerTenants | ? {($_.id -like "*$fromtenant*")}

        $DestAPIHost = $DestTenantSearch.apiHost
        $FromTenantHost = $FromTenantSearch.apiHost
        
    Write-host ""
    Write-host "Endpoint Migration Requested" -ForegroundColor Green
    Write-host ""
    Write-host "Moving the Endpoint ID: $endpointid" -ForegroundColor Green
    Write-host ""
    Write-host "From Tenant: " $FromTenantSearch.name "("$FromTenantSearch.id")" -ForegroundColor Green
    Write-host ""
    Write-host "To Tenant: " $DestTenantSearch.name "("$DestTenantSearch.id")" -ForegroundColor Green
    Write-host ""
    Write-host ""
    Write-host "Please ensure that Endpoint Migration is enabled in Central Admin - Global Settings or"
    Write-host ""
    Write-host "Central Partner - Global Templates - Global Settings"
    Write-host ""
    Write-host ""
    
    $confirm = Read-Host -Prompt 'Is the above Info Correct and Endpoint Migrations Enabled? (Y/N)'

    if ($confirm -eq "Y")
    {
        # SOPHOS Endpoint Migration URI:
	        $ReceiveURI = "$DestAPIHost/endpoint/v1/migrations"
                    	
        # Migration Receive Headers:
            $ReceiveHeaders = @{
                "Content-Type" = "application/json";
                "Authorization" = "Bearer $Global:Token";
                "X-Tenant-ID" = $desttenant;
                }

        # Migration Send Headers:
            $SendHeaders = @{
                "Content-Type" = "application/json";
                "Authorization" = "Bearer $Global:Token";
                "X-Tenant-ID" = $fromtenant;
                }
            
         #Migration Receive Data
            $ReceiveData = "{`"fromTenant`" : `"$fromtenant`",`"endpoints`" : [`"$endpointid`"]}"

         # Receive Job Results
	        $ReceiveJob = (Invoke-RestMethod -Method Post -Uri $ReceiveURI -Headers $ReceiveHeaders -Body $ReceiveData)

         #Migration Send URI
            $SendURI = "$FromTenantHost/endpoint/v1/migrations/" + $ReceiveJob.id

         #Migration Send Data
            $SendToken = $ReceiveJob.token
            $SendData = "{`"token`" : `"$SendToken`",`"endpoints`" : [`"$endpointid`"]}"
    
         #Send Job Results
            $SendJob = (Invoke-RestMethod -Method Put -Uri $SendURI -Headers $SendHeaders -Body $SendData)

        Write-host ""
        Write-host ""
        Write-host "Migration Job ID: " $SendJob.id -ForegroundColor Green
        Write-host ""
        Write-host ""
        
        $global:MigrationID = $SendJob.id
    
    }
    else
    {
        Write-host "No or invalid selection made"
    }


}

function Get-MigrationStatus{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Get the latest list of partners with the ID, API Host and Name
    Get-SOPHOSPartnerTenants

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Migration Status Headers:
            $StatusHeaders = @{
                "Content-Type" = "application/json";
                "Authorization" = "Bearer $Global:Token";
                "X-Tenant-ID" = $desttenant;
                }

    #Set Tenant Names

        $DestTenantSearch = $global:PartnerTenants | ? {($_.id -like "*$desttenant*")}
        $DestAPIHost = $DestTenantSearch.apiHost
        	
	# SOPHOS Migration Status URI:
	    $StatusURI = "$DestAPIHost/endpoint/v1/migrations/$MigrationID/endpoints"
	
	#MigrationStatus
		$MigrationStatus = (Invoke-RestMethod -Method Get -Uri $StatusURI -Headers $StatusHeaders)
    
    Write-host ""
    Write-host ""
    Write-host "Endpoint Migration Status"-ForegroundColor Green
    Write-host ""
    Write-host $MigrationStatus.items -ForegroundColor Green
    Write-host ""
    
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
    Write-Host "3: Search Tenants"
    Write-Host "4: Migrate Endpoint"
    Write-Host "5: Migration Status"
	Write-Host "6: Delete Token"
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
    } 
    
    '2' {
    Write-host ""
	$computername = Read-Host -Prompt 'Enter the Full or Partial Computer Name your looking for'
    Get-SOPHOSPartnerEndpointsAllTenants -hostname $computername
    } 
    
    '3' {
    Write-host ""
	$companyname = Read-Host -Prompt 'Enter the Full or Partial Company Name your looking for'
    Get-SOPHOSPartnerTenantSearch
    } 
    
    '4' {
    Write-host ""
	$global:desttenant = Read-Host -Prompt 'Enter the Destination Tenant ID'
    $global:fromtenant = Read-Host -Prompt 'Enter the Current Tenant ID'
    $endpointid = Read-Host -Prompt 'Enter the Endpoint ID'
    Get-EndpointMigration
    }
    
    '5' {
    Write-host ""
	Get-MigrationStatus
    }  
    
    '6' {
	 if ((Test-Path $env:userprofile\sophos_partner_secureaccess.json) -eq $true){
        Remove-item $env:userprofile\sophos_partner_secureaccess.json
		Write-host ""
		Write-host "***Sophos Central Token Deleted***" -foregroundcolor Green
		Write-host ""
        }
		Else {
        Write-host ""
        Write-host "***Sophos Central Token Not Found***" -foregroundcolor Red
        Write-host ""
        }
	}
    }
    pause
 }
 until ($selection -eq 'q')
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
	$InitialResult = (Invoke-RestMethod -Method Get -Uri $PartnerTenantURI -Headers $PartnerTenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
    
    # Check them all into this collection
    $AllPartnerTenantResults = @()
    
    for ($i = 1; $i -le $InitialResult.pages.total; $i++) {
        $PagedURI = "https://api.central.sophos.com/partner/v1/tenants?pageTotal=True&page=$i"
        $PagedResult = Invoke-RestMethod -Method Get -Uri $PagedURI -Headers $PartnerTenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error
        
        if ($PagedResult.items) {
            $AllPartnerTenantResults += $PagedResult.items
        }
    }

    # Store the result globally
    $global:PartnerTenants = $AllPartnerTenantResults | Select-Object -Property id, name, apiHost

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
	        $AllTenantEndpointResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints?pageSize=500&search="$computername"&searchField=hostname" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
        }

        # Display the Search Results
            foreach ($hostname in $AllTenantEndpointResult.items) {
            $computer = $hostname.hostname
            $id = $hostname.id
            $tamperprotection = $hostname.tamperProtectionEnabled
            $person = $hostname.associatedPerson.name
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
            #break
        }

Write-Host ""
Write-Host "Search Complete" -ForegroundColor Yellow
Pause
}

function Get-EndpointInTenant{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Set Partner Tenant URI
        $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants"
			
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
	    $AllTenantEndpointResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints?pageSize=500&search="$computername"&searchField=hostname" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
	
    # Display the Results
        
            foreach ($hostname in $AllTenantEndpointResult.items) {
            $computer = $hostname.hostname
            $id = $hostname.id
            $tamperprotection = $hostname.tamperProtectionEnabled
            $person = $hostname.associatedPerson.name
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
            #break

Write-Host ""
Write-Host "Search Complete" -ForegroundColor Yellow
Pause
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
			$global:TenantApiHost = $name.apiHost
            Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "Tenant Name: $cname"  -ForegroundColor Green
			Write-host ""
            Write-host "Tenant ID: $id"  -ForegroundColor Green
            Write-host ""
            Write-host "API Host: $global:TenantApiHost" -ForegroundColor Green
			Write-host "***********************"
            }
  Write-Host ""
  Write-Host "Search Complete" -ForegroundColor Yellow
  Pause      
    }

function Get-EndpointMigration{
    #Script Notice
        Write-host ""
        Write-host "Running the Endpoint Migration Prerequites" -ForegroundColor Yellow
        Write-host ""

    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Get the latest list of partners with the ID, API Host and Name
    Get-SOPHOSPartnerTenants

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Set Partner Tenant URI
        $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants"

    # Variable Input
        Write-host ""
        Write-host "***Endpoint Migration Tool***"
        Write-host ""

        $DestTenant = Read-Host -Prompt 'Enter the Destination Tenant ID'
        $FromTenant = Read-Host -Prompt 'Enter the Current Tenant ID'
        $EndpointId = Read-Host -Prompt 'Enter the Endpoint ID(s) (comma-separated for multiple)'
    
    # Set Tenant Names and API Host

        $DestTenantSearch = $PartnerTenants | Where-Object { $_.id -like "$DestTenant" }   
        $FromTenantSearch = $PartnerTenants | Where-Object { $_.id -like "$FromTenant" }

        $DestAPIHost = $DestTenantSearch.apiHost
        $FromTenantHost = $FromTenantSearch.apiHost
        
    Write-host ""
    Write-host "***Endpoint Migration Requested***" -ForegroundColor Green
    Write-host ""
    Write-host "Moving the Endpoint ID: $endpointid" -ForegroundColor Green
    Write-host ""
    Write-host "From Tenant: " $FromTenantSearch.name "("$FromTenant")" -ForegroundColor Green
    Write-host "From Tenant API: " $FromTenantHost -ForegroundColor Yellow
    Write-host ""
    Write-host "To Tenant: " $DestTenantSearch.name "("$DestTenant")" -ForegroundColor Green
    Write-host "From Tenant API: " $DestAPIHost -ForegroundColor Yellow
    Write-host ""
    Write-host ""
    Write-host "Please ensure that Endpoint Migration is enabled in Central Admin - Global Settings or"
    Write-host ""
    Write-host "Central Partner - Global Templates - Global Settings"
    Write-host ""
    Write-host ""
    
    $confirm = Read-Host -Prompt 'Is the above Info Correct and Endpoint Migrations Enabled? (Y/N)'

    if ($confirm.ToUpper() -eq "Y")
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

        # Convert EndpointIDs to an Array
			$endpointarray = "$endpointid" -split ','

			$stringBuilder = New-Object -TypeName "System.Text.StringBuilder"

			[void]$stringBuilder.Append("")
				foreach($endpoint in $endpointarray)
					{
						[void]$stringBuilder.Append("`"$endpoint`",")
					}
				$endpointoutput = $stringBuilder.ToString()

				$endpointdata = $endpointoutput.Substring(0,$endpointoutput.Length-1)
          
        # Migration Receive Data
            $ReceiveData = "{`"fromTenant`" : `"$fromtenant`",`"endpoints`" : [$endpointdata]}"

        # Receive Job Results
	        $ReceiveJob = (Invoke-RestMethod -Method Post -Uri $ReceiveURI -Headers $ReceiveHeaders -Body $ReceiveData)

        #Migration Send URI
            $SendURI = "$FromTenantHost/endpoint/v1/migrations/" + $ReceiveJob.id

        #Migration Send Data
            $SendToken = $ReceiveJob.token
            $SendData = "{`"token`" : `"$SendToken`",`"endpoints`" : [$endpointdata]}"
    
        #Send Job Results
            $SendJob = (Invoke-RestMethod -Method Put -Uri $SendURI -Headers $SendHeaders -Body $SendData)

        Write-host ""
        Write-host "***Migration Job Details***"
        Write-host ""
        Write-host "Migration Job ID: " $SendJob.id -ForegroundColor Green
        Write-host ""
        Write-host "Destination Tenant ID: " $DestTenant -ForegroundColor Green
        Write-host ""
        Write-host "Please Migration ID and Destination Tenant ID as they will be required for the Migration Status" -ForegroundColor Green
        Write-host ""
    }
    else
    {
        Write-host ""
        Write-host "No or invalid selection made"  -ForegroundColor Yellow
        Write-host ""
    }

Pause
}

function Get-MigrationStatus{
    #Script Notice
        Write-host ""
        Write-host "Running the Migration Status Prerequites" -ForegroundColor Yellow
        Write-host ""

    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Get the latest list of partners with the ID, API Host and Name
    Get-SOPHOSPartnerTenants

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Variable Input
        Write-host ""
        Write-host "***Migration Status***"
        Write-host ""

        $DestTenant = Read-Host -Prompt 'Enter the Destination Tenant ID'
        $MigrationID = Read-Host -Prompt 'Enter the Migration ID'
        
    # Set API Host

        $DestTenantSearch = $PartnerTenants | Where-Object { $_.id -like "$DestTenant" }
        $DestAPIHost = $DestTenantSearch.apiHost

    # Migration Status Headers:
            $StatusHeaders = @{
                "Content-Type" = "application/json";
                "Authorization" = "Bearer $Global:Token";
                "X-Tenant-ID" = $DestTenant;
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
    Write-host "***Endpoint Migration Status***"-ForegroundColor Green
    Write-host ""
    Write-host "Migration Destination:" $DestTenantSearch.name -ForegroundColor Green
    Write-host ""
    Write-host "Status :" $MigrationStatus.items.status -ForegroundColor Green
    Write-host ""
  
  Pause  
}

function Get-SophosAddBlockedItem{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
    # Get the latest list of partners with the ID, API Host and Name
    Get-SOPHOSPartnerTenants

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Set Partner Tenant URI
            $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants"
    		
        foreach ($id in $global:PartnerTenants) {
            Start-Sleep -Seconds 1
			$tenant_id = $id.id
			$tenant_ApiHost = $id.apiHost
            
			$block_URI = $tenant_ApiHost + "/endpoint/v1/settings/blocked-items"
			
			$BlockHeaders = @{
                "Content-Type" = "application/json";
                "Authorization" = "Bearer $Global:Token";
                "X-Tenant-ID" = $tenant_id;
                }
			
			$BlockData = "{`"type`": `"sha256`",`"properties`": {`"sha256`": `"$hashdata`"},`"comment`": `"$commentdata`"}"
			
			Invoke-RestMethod -Method Post -Uri $block_URI -Headers $BlockHeaders -Body $BlockData
            }
                
    }

function Get-DownloadURLs{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	                 	
    # Headers
    
    $PartnerTenantHeaders = @{
        "Authorization" = "Bearer $global:Token";
        "X-Partner-ID" = "$global:ApiPartnerId";
        }
    
    $TenantHeaders = @{
        "Authorization" = "Bearer $global:Token";
        "X-Tenant-ID" = $customerid;
        }

    # Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    #Get Tenant Info
    
    $TenantData = (Invoke-RestMethod -Method Get -Uri "https://api.central.sophos.com/partner/v1/tenants/$customerid" -Headers $PartnerTenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
    $TenantURL = $TenantData.apiHost
    
    #Get Download Data
    $DownloadData = (Invoke-RestMethod -Method Get -Uri $TenantURL"/endpoint/v1/downloads?requestProducts=$ProductCode&platforms=$OS" -Headers $TenantHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )

    $Installers = $DownloadData.installers
    
	foreach ($productName in $Installers) {
            $product = $productName.productName
			$platform = $productName.platform
			$type = $productName.type
			$url = $productName.downloadUrl
            Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "Product Name: $product"  -ForegroundColor Green
			Write-host ""
            Write-host "Platform: $platform"  -ForegroundColor Green
            Write-host ""
			Write-host "OS Type: $type"  -ForegroundColor Green
			Write-host ""
			Write-host "Download URL: $url" -ForegroundColor Green
			Write-host "***********************"
            }
    pause
    }

function Get-FirewallsAllTenants{
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
             $AllTenantFirewallResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/firewall/v1/firewalls" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
        }
    
        # Display the Search Results
            foreach ($hostname in $AllTenantFirewallResult.items) {
            $firewallname = $hostname.hostname
            $model = $hostname.model
            $firmware = $hostname.firmwareVersion
            Write-Host "**************"
            Write-Host "$firewallname"
            Write-Host "$model"
            Write-host "$firmware"
            Write-Host "$tenantname"
            Write-Host "**************"
            Write-Host "**Searching***"
            Write-Host "**************"

            [pscustomobject]@{FirewallName = $firewallname; Model = $model; Firmware = $firmware; CustomerName = $tenantname } | Export-Csv -Append -Path ".\FirewallList.csv" -NoTypeInformation

            }
            #break
        }
    
Write-Host ""
Write-Host "Export Complete" -ForegroundColor Yellow
Pause
}

function Get-ExtendedSupportAllTenants{
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
             $ExtendedSupportOSResult = (Invoke-RestMethod -Method Get -Uri $apiHost"/endpoint/v1/endpoints?search=$osVersion&searchFields=osName" -Headers $TentantAPIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
        }
    
        # Display the Search Results
            foreach ($hostname in $ExtendedSupportOSResult.items) {
            $computername = $hostname.hostname
            $os = $hostname.os.name
            Write-Host "**************"
            Write-Host "$computername"
            Write-Host "$os"
            Write-Host "$tenantname"
            Write-Host "**************"
            Write-Host "**Searching***"
            Write-Host "**************"

            [pscustomobject]@{ComputerName = $computername; OS = $os; CustomerName = $tenantname } | Export-Csv -Append -Path ".\ExtendedSupportList.csv" -NoTypeInformation

            }
            #break
        }
    
Write-Host ""
Write-Host "Export Complete" -ForegroundColor Yellow
Pause
}

function OS_Selection {
    param (
        [string]$Title = 'OS'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host ""
    Write-Host "1: Windows"
    Write-Host "2: macOS"
    Write-Host "3: Linux"
}

function Product_Selection {
    param (
        [string]$Title = 'Installers'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host ""
    Write-Host "1: Intercept X Essentials/Advanced"
    Write-Host "2: Intercept X Adv with XDR"
    Write-Host "3: Sophos MDR"
}

function Search_Menu {
    param (
        [string]$Title = 'Search'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host ""
    Write-Host "1: Set the Tenant ID"
    Write-Host "2: Search the Tenant for a Computer"
    Write-Host "b: Back to Main Menu"
}

function OSVersion_Menu {
    param (
        [string]$Title = 'Extended Support'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host ""
    Write-Host "1: Search for Windows 7"
    Write-Host "2: Search for Windows 8"
    Write-Host "3: Search for Windows 2003"
    Write-Host "4: Search for Windows 2008"
    Write-Host "5: Search for Windows 2012"
    Write-Host "B: Back to Main Menu"
}

function Show-Menu {
    param (
        [string]$Title = 'Sophos Central API Access'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host ""
    Write-Host "1: Get Sophos Central API Token"
    Write-Host "2: Global Search for an Endpoint"
    Write-Host "3: Search for a Tenant"
	Write-Host "4: Search Tenant for an Endpoint"
    Write-Host "5: Migrate Endpoint"
    Write-Host "6: Migration Status"
    Write-Host "7: Export Firewall List"
	Write-Host "8: Block SHA256 on all Tenants"
	Write-Host "9: Get Download URLs"
    Write-Host "E: Export Extended Support OS List"
	Write-Host "D: Delete Token"
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
    Get-SOPHOSPartnerEndpointsAllTenants
    } 
    
    '3' {
    Write-host ""
	$companyname = Read-Host -Prompt 'Enter the Full or Partial Company Name your looking for'
    Get-SOPHOSPartnerTenantSearch
    } 
    
	'4' {
       do
	{
    Search_Menu
    Write-Host ""
    $search_selection = Read-Host "Please make a selection"
    switch ($search_selection)
    {
    '1' {
    Write-host ""
	$customerid = Read-Host -Prompt 'Enter Tenant ID to search'
    } 
    
    '2' {
    Write-Host ""
	$computername = Read-Host -Prompt 'Enter the Full or Partial Computer Name your looking for'
	Get-EndpointInTenant
    } 
   
	}
    }
    until ($search_selection -eq 'b')
	}
	
    '5' {
    Write-host ""
    Get-EndpointMigration
    }
    
    '6' {
    Write-host ""
	Get-MigrationStatus
    }  
    
    '7' {
    Write-host ""
    Get-FirewallsAllTenants
    }
	
    '8' {
    Write-host ""
	$hashdata = Read-Host -Prompt 'Enter the SHA256 Hash ID'
    $commentdata = Read-Host -Prompt 'Enter the Comment'
    Get-SophosAddBlockedItem
    }
	
	'9' {
    Write-host ""
	$customerid = Read-Host -Prompt 'Tenant ID'

    do
 {
    OS_Selection
    Write-Host ""
    $os_selection = Read-Host "Please make a selection"
    switch ($os_selection)
    {
    '1' {
    $OS = "windows"
    } 
    
    '2' {
    $OS = "macOS"
    } 
    
    '3' {
    $OS = "linux"
    } 
	}
    }
    until ($os_selection)
	
    do
 {
    Product_Selection
    Write-Host ""
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    '1' {
    $ProductCode = "endpointProtection,interceptX"
    } 
    
    '2' {
    $ProductCode = "endpointProtection,interceptX,xdr"
    } 
    
    '3' {
    $ProductCode = "endpointProtection,interceptX,xdr,mtr"
    } 
	}
    }
    until ($selection)
	Get-DownloadURLs
    }
	    
	'e' {
        do
     {
     OSVersion_Menu
     Write-Host ""
     $versionSelection = Read-Host "Please make a selection"
     switch ($versionSelection)
     {
     '1' {
     Write-host "Windows 7 Selected"
     $Global:osVersion = "7"
     Get-ExtendedSupportAllTenants
     } 
     
     '2' {
     Write-host "Windows 8 Selected"
     $Global:osVersion = "8"
     Get-ExtendedSupportAllTenants
     } 

     '3' {
     Write-host "Windows 2003 Server Selected"
     $Global:osVersion = "2003"
     Get-ExtendedSupportAllTenants
     } 

     '4' {
     Write-host "Windows 2008 Server Selected"
     $Global:osVersion = "2008"
     Get-ExtendedSupportAllTenants
     } 

     '5' {
     Write-host "Windows 2012 Server Selected"
     $Global:osVersion = "2012"
     Get-ExtendedSupportAllTenants
     }
     
     }
     }
     until ($search_selection -eq 'b')
     Show_Menu 
     }
     
   'd' {
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
 }
 until ($selection -eq 'q')
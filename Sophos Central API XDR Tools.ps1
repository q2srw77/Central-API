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

function Sophos_XDR_Post{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	
	#Set Partner Tenant URI
            $PartnerTenantURI = "https://api.central.sophos.com/partner/v1/tenants"
    
	# Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

	# SOPHOS Customer Tenant API Headers:
		 
        $APIHeaders = @{
            "Authorization" = "Bearer $global:Token";
            "X-Partner-ID" = "$global:ApiPartnerId";
        }
		
		$TentantAPIHeaders1 = @{
            "Authorization" = "Bearer $global:Token";
            "X-Tenant-ID" = "$Global:xdrtenant1";
            "Content-Type" = "application/json";
        }
		
		$TentantAPIHeaders2 = @{
            "Authorization" = "Bearer $global:Token";
            "X-Tenant-ID" = "$Global:xdrtenant2";
            "Content-Type" = "application/json";
        }
    
	#Post Data for Powershell
		
		$xdrdata = "{`"savedQuery`": {`"queryId`": `"082c521a-6300-4e9d-8ce0-946ee70dc598`",`"categoryId`":`"76fced42-1de6-4952-95be-1c9633e6e9a3`"},`"variables`":[{`"name`":`"process_name`",`"dataType`":`"text`",`"value`":`"$global:process_name`"}],`"from`":`"$Global:xdrfrom`",`"to`":`"$Global:xdrto`"}"
    
    # Build the XDR query for Tenant 1
        
		$tenant1apiHost = (invoke-RestMethod -Method Get -Uri "https://api.central.sophos.com/partner/v1/tenants/$Global:xdrtenant1" -Headers $APIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
		
		$XDRTenant1apihost = $tenant1apiHost.apiHost
        
		$XDRPostTenant1 = (invoke-RestMethod -Method Post -Uri $XDRTenant1apihost"/xdr-query/v1/queries/runs" -Headers $TentantAPIHeaders1 -Body $xdrdata -ErrorAction SilentlyContinue -ErrorVariable Error)
            
		$Global:XDRTenant1QueryID = $XDRPostTenant1.id
					
			Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "XDR Tenant 1 Query ID: $XDRTenant1QueryID"  -ForegroundColor Green
			Write-host ""
			Write-host "***********************"

    # Build the XDR query for Tenant 2
		$tenant2apiHost = (invoke-RestMethod -Method Get -Uri "https://api.central.sophos.com/partner/v1/tenants/$Global:xdrtenant2" -Headers $APIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error)
		
		$XDRTenant2apihost = $tenant2apiHost.apiHost
        
		$XDRPostTenant2 = (invoke-RestMethod -Method Post -Uri $XDRTenant2apihost"/xdr-query/v1/queries/runs" -Headers $TentantAPIHeaders2 -Body $xdrdata -ErrorAction SilentlyContinue -ErrorVariable Error)
            
		$Global:XDRTenant2QueryID = $XDRPostTenant2.id
			
			
			Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "XDR Tenant 2 Query ID: $XDRTenant2QueryID"  -ForegroundColor Green
			Write-host ""
			Write-host "***********************"

Write-Host ""
Write-Host "Results may take a minute to process" -ForegroundColor Yellow
Write-Host ""
Write-Host "Post Complete" -ForegroundColor Yellow
Pause
}

function Sophos_XDR_Results{
    # Before the function runs check the token expiry and regenerate if needed
    Get-SOPHOSTokenExpiry
	    
	# Set TLS Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    # SOPHOS Customer Tenant API Headers:
		 
        $APIHeaders = @{
            "Authorization" = "Bearer $global:Token";
            "X-Partner-ID" = "$global:ApiPartnerId";
        }
		
		$TentantAPIHeaders1 = @{
            "Authorization" = "Bearer $global:Token";
            "X-Tenant-ID" = "$xdrtenant1";
        }
		
		$TentantAPIHeaders2 = @{
            "Authorization" = "Bearer $global:Token";
            "X-Tenant-ID" = "$xdrtenant2";
        }

	#Get Results from XDR Queries
		$tenant1apiHost = (invoke-RestMethod -Method Get -Uri "https://api.central.sophos.com/partner/v1/tenants/$Global:xdrtenant1" -Headers $APIHeaders -ErrorAction SilentlyContinue -ErrorVariable Error )
		
		$XDRTenant1apihost = $tenant1apiHost.apiHost

		$xdrresults1 = (invoke-RestMethod -Method Get -Uri $XDRTenant1apihost"/xdr-query/v1/queries/runs/"$Global:XDRTenant1QueryID"/results" -Headers $TentantAPIHeaders1 -ErrorAction SilentlyContinue -ErrorVariable Error)
		
		#$xdrresults2 = (invoke-RestMethod -Method Get -Uri $XDRTenant2apihost"/xdr-query/v1/queries/runs/"$Global:XDRTenant2QueryID"/results" -Headers $TentantAPIHeaders1 -ErrorAction SilentlyContinue -ErrorVariable Error)
    		
        foreach ($result in $xdrresults1.items) {
            $fseen = $result.first_seen
			$pname = $result.process_name
			$cmd = $result.cmd_line
            $device = $result.ep_list
            $sha = $result.sha256
            Write-host ""
			Write-host "***********************"
			Write-host ""
			Write-host "First Seen: $fseen"  -ForegroundColor Green
			Write-host ""
            Write-host "Device Name: $device" -ForegroundColor Green
            Write-host ""
            Write-host "Process Name: $pname"  -ForegroundColor Green
            Write-host ""
            Write-host "SHA256: $sha" -ForegroundColor Green
            Write-host ""
            Write-host "Command Line: $cmd" -ForegroundColor Green
			Write-host "***********************"
            }
  Write-Host ""
  Write-Host "Results Complete" -ForegroundColor Yellow
  Pause
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

function Show-Menu {
    param (
        [string]$Title = 'Sophos Central API XDR Search'
    )
    Clear-Host
    Write-Host "================ $Title ================"
    Write-Host ""
    Write-Host "1: Get Sophos Central API Token"
    Write-Host "2: Search for Endpoint"
    Write-Host "3: Search Tenants"
    Write-Host "4: XDR Set Tenant IDs"
	Write-Host "5: XDR Set Date Range"
	Write-Host "6: XDR Query (Process Name)"
	Write-Host "7: XDR Get Query ID Results"
	Write-Host "8: Block SHA256 on all Tenants"
	Write-Host "9: Delete Token"
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
	$Global:xdrtenant1 = Read-Host -Prompt 'Enter Tenant 1 ID'
    $Global:xdrtenant2 = Read-Host -Prompt 'Enter Tenant 2 ID'
    Write-host ""
    Write-host "Verify the Tenant IDs"
    Write-host ""
    Write-host "Tenant 1 = $Global:xdrtenant1"
    Write-host ""
    Write-host "Tenant 2 = $Global:xdrtenant1"
	pause
    }
 
	'5' {
    Write-host ""
	$Global:xdrfrom = Read-Host -Prompt 'Enter From Date (year-month-day)'
    $Global:xdrto = Read-Host -Prompt 'Enter To Date (year-month-day)'
    Write-host ""
    Write-host "Verify the Dates"
    Write-host ""
    Write-host "From = $Global:xdrfrom"
    Write-host ""
    Write-host "To = $Global:xdrto"
	pause
    }
	
	'6' {
    Write-host ""
	$global:process_name = Read-Host -Prompt 'Enter the Process Name including extension'
    Sophos_XDR_Post
    } 
      
	'7' {
    Write-host ""
    Sophos_XDR_Results
    }
	
	'8' {
    Write-host ""
	$hashdata = Read-Host -Prompt 'Enter the SHA256 Hash ID'
    $commentdata = Read-Host -Prompt 'Enter the Comment'
    Get-SophosAddBlockedItem
    }
		
    '9' {
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
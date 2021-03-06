﻿<#
 
.SYNOPSIS
    Module contains a library of functions for the FireEye HX API
 
.DESCRIPTION
    This PowerShell Module is intended to be a library of functions used to access
    and manage the API of a FireEye HX server.

.NOTES
    This Module is incomplete as of 8/14/2017. 

    I'm currently working to complete the Indicators and Conditions secion
    
    Author: Jeff Williams
    Email: jeff@cybergrits.com
    Date: 7/1/2017
 
#>




$Server = "x.x.x.x"
$Port = "3000"
$Url = "https://$Server`:$Port"


#------------------#
#  Authentication  #
#------------------#

# Enables the use of Self Signed Certs
 Function Ignore-SelfSignedCerts {
<#
.EXAMPLE
    Ignore-SelfSignedCerts
#> 
    try
    {
 
        Write-Host "Adding TrustAllCertsPolicy type." -ForegroundColor White
        Add-Type -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy
        {
                public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem)
                {
                    return true;
            }
        }
"@
 
        Write-Host "TrustAllCertsPolicy type added." -ForegroundColor White
        }
    catch
        {
        Write-Host $_ -ForegroundColor "Yellow"
        }
 
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
 
# Authenticates to the HX Server and returns a user Token
Function HX-Auth {
<#
.EXAMPLE
    HX-Auth -URL https://hxserver:3000

.EXAMPLE
    HX-Auth -URL $url
#>

    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL
        )

    # Prompts for and processes API user creds   
    $c = Get-Credential -Message "Enter HX API Credentials"
    $cpair = "$($c.username):$($c.GetNetworkCredential().Password)"
    $key = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cpair))
   
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "Authorization" = "Basic $key"
        }
   
    # Authenticates to the HX server
    $gettoken = Invoke-WebRequest -Uri "$URL/hx/api/v3/token" -Headers $header -Method Get
    # Gets just the Token info from the get request 
    $token = $gettoken.Headers.'X-FeApi-Token'
    $token
    }
 
# Logs off API user of supplied Token
Function HX-DeAuth {
<#
.EXAMPLE
    HX-DeAuth -URL https://hxserver:3000 -Token ILRw5UaMD8DffEXrN45phSl7jxqPAU4fwKeWM1yDFgGGA28=

.EXAMPLE
    HX-DeAuth -URL $url -Token $token
#>

    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    $apiLogOff = Invoke-WebRequest -Uri "$URL/hx/api/v3/token" -Headers $header -Method Delete
    if($apiLogOff.StatusCode -eq "204"){Write-Host "User Successfully Logged Off." -ForegroundColor Cyan}
    }



#-----------#
#  Version  #
#-----------#
 
# Returns a list of All hosts in FireEye
Function HX-Get-Version {
<#
.EXAMPLE
    HX-Get-Version -URL https://hxserver:3000 -Token ILRw5UaMD8DffEXrN45phSl7jxqPAU4fwKeWM1yDFgGGA28=

.EXAMPLE
    HX-Get-Version -URL $url -Token $token
#>

    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token
        )
    
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Gets HX Version
    $hxVersion = Invoke-RestMethod -Uri "$URL/hx/api/v3/version" -Headers $header -Method Get
    $hxVersion.data
    }



#--------------------#
#  Host Information  #
#--------------------#
 
# Returns a list of All hosts in FireEye
Function HX-Get-Hosts {
<#
.EXAMPLE
    HX-Get-Hosts -URL https://hxserver:3000 -Token ILRw5UaMD8...

.EXAMPLE
    HX-Get-Hosts -URL $url -Token $token -Limit 100
#>
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$Limit='35000'
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)
    $FireEyeHosts = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts?$Limit" -Headers $header -Method Get
    $FireEyeHosts.data
    }
 
# Searches HX for a host
Function HX-Search-Hosts {
<#
.SYNOPSIS
    Searches HX for terms provided related to hosts. Terms should be full or partial hostnames,
    IP addresses, MAC addresses, operating system, etc...

.EXAMPLE
    HX-Search-Hosts -URL https://hxserver:3000 -Token ILRw5U... -Search host123 

.EXAMPLE
    HX-Search-Hosts -URL $url -Token $token -Search $search -Limit 1
#>

    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Search,
        [string]$Limit="35000"
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Searches HX for a host that matches the search object
    $FireEyeSearch = Invoke-RestMethod -Method Get -Uri "$URL/hx/api/v3/hosts?limit=$Limit&search=$Search" -Headers $header
    $FireEyeSearch.data
    }
 
# Delete Host based off Agent ID
Function HX-Del-Host {
<#
.SYNOPSIS
    Deletes a host from HX using either the Agent ID. If the ID is not known the hostname
    can be used and will use HX-Search-Hosts to find the ID
.REQUIRMENTS
    HX-Search-Hosts
.EXAMPLE
    HX-Del-Host -URL https://hxserver:3000 -Token ILRw5U... -Hostname host123 
.EXAMPLE
    HX-Del-Host -URL $url -Token $token -AgentID RolTnVIx...
.EXAMPLE
    HX-Del-Host -URL $url -Token $token -Hostname host123
#>

    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$AgentID,
        [string]$Hostname
        )
    
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    if($AgentID){
        # Deletes a host from HX using it's AgentID
        $DeleteHost = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID" -Headers $header -Method Delete 
        $DeleteHost
        }
    elseif($Hostname){
        # Searches HX for the hostname and returns the AgentID
        $HID = (HX-Search-Hosts -URL $URL -Token $Token -Search $Hostname -Limit 1).entries._id

        # Deletes a host from HX using it's AgentID
        $DeleteHost = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$HID" -Headers $header -Method Delete 
        $DeleteHost
        }
    else{Write-Error "Missing HostName or AgentID."}
    }
 
# Get Agent configuration for a host
Function HX-Get-AgentConf {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$AgentID,
        [string]$Hostname
        )
    
    # Required Header information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    If($AgentID){
        # Gets agent config for a given AgentID
        $AgentConf = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID/configuration/actual.json" -Headers $header -Method Get
        $AgentConf
        }
    ElseIf($Hostname){
        # Searches HX for the hostname and returns the AgentID
        $HID = (HX-Search-Hosts -URL $URL -Token $Token -Search $Hostname -Limit 1).entries._id

        # Gets agent config for a given AgentID
        $AgentConf = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$HID/configuration/actual.json" -Headers $header -Method Get
        $AgentConf
        }
    Else{Write-Error "Missing HostName or AgentID."}
    }
 
 


#-------------#
#  Host Sets  #
#-------------#

# New Static Host Set Request
Function HX-Add-StaticHostSet {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [string[]]$AddHosts
        )
    
    # Required Header information
    $header = @{
        "Accept" = "application/json"
        #"Content-Type" = "application/json"
        "X-FeApi-Token" = "$Token"
        }

    # Creates Host Set using Name and Hosts Provided
    if($AddHosts){
        $Body =@{
            name = "$Name"
            changes = @(
                @{
                    command = "change"
                    add = @($AddHosts)
                    }
                )
            }
        # Converts Body to json
        $json = $Body | ConvertTo-Json -Depth 4 -Compress
        
        # Adds Static Host Set
        $addHostSet = irm -Method Post -Uri "$URL/hx/api/v3/host_sets/static" -Headers $header -Body $json -ContentType 'application/json'
        $addHostSet.data
        }
    # Creates Host Set using provided Name
    Else{
        $Body =@{
            name = "$Name"
            changes = @(
                @{
                    command = "change"
                    # add = @($AddHosts)
                    }
                )
            }
        # Converts Body to json
        $json = $Body | ConvertTo-Json -Depth 4 -Compress
        
        # Adds Static Host Set
        $addHostSet = irm -Method Post -Uri "$URL/hx/api/v3/host_sets/static" -Headers $header -Body $json -ContentType 'application/json'
        $addHostSet.data
        }
    }

# Update a Static Host Set Request
Function HX-Mod-StaticHostSet {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [string[]]$AddHost,
        [string[]]$RemoveHost
        )
    
    # Required Header information
    $header = @{
        "X-FeApi-Token" = "$Token"
        }

    # Gets the ID of the Host Set using the Name info provided
    $HSID = ((HX-Get-HostSet -URL $URL -Token $Token).data.entries) |Where-Object {$_.name -eq "$Name"} | select _id

    If($HSID){
        # Sets up the Body to convert to json
        If($AddHost){
            $Body =@{
                name = "$Name"
                changes = @(
                    [PSCustomObject]@{
                        command = "change"
                        add = @($AddHost)
                        }
                    )
                }
            # Converts to json
            $json = $Body | ConvertTo-Json -Depth 5
                        
            # Modifies Static Host Set
            $ModHostSet = irm -Method Put -Uri "$URL/hx/api/v3/host_sets/static/$($HSID._id)" -Headers $header -Body $json -ContentType 'application/json'
            $ModHostSet.data
            }
        Elseif($RemoveHost){
            $Body =@{
                name = "$Name"
                changes = @(
                    [PSCustomObject]@{
                        command = "change"
                        remove = @($RemoveHost)
                        }
                    )
                }
            # Converts to json
            $json = $Body | ConvertTo-Json -Depth 5
            
            # Modifies Static Host Set
            $ModHostSet = irm -Method Put -Uri "$URL/hx/api/v3/host_sets/static/$($HSID._id)" -Headers $header -Body $json -ContentType 'application/json'
            $ModHostSet.data
            }
        Else{Write-Error "Must Supply -AddHost or -RemoveHost"}
        }
    Else{Write-Error "Host Set Not Found"}
    }

# New Dynamic Host Set Request
Function HX-Add-DynamicHostSet {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Body
        )
    
    # Required Header information
    $header = @{
        "X-FeApi-Token" = "$Token"
        }
    
    # Adds Dynamic Host Set using JSON provided as Body
    $addHostSet = irm -Method Post -Uri "$URL/hx/api/v3/host_sets/dynamic" -Headers $header -Body $Body -ContentType 'application/json'
    $addHostSet.data
    }

# Update a Dynamic Host Set Request
Function HX-Mod-DynamicHostSet {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Body
        )
    
    # Required Header information
    $header = @{
        "X-FeApi-Token" = "$Token"
        }
    
    # Adds Dynamic Host Set using JSON provided as Body
    $addHostSet = irm -Method Put -Uri "$URL/hx/api/v3/host_sets/dynamic" -Headers $header -Body $Body -ContentType 'application/json'
    $addHostSet.data
    }

# List of Host Sets or info on a single Host Set if ID is provided
Function HX-Get-HostSet {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$Name,
        [string]$Limit="100"
        )
    
    # Required Header information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }

    # Gets the ID of the Host Set using the Name info provided
    $HSID = ((irm -Uri "$URL/hx/api/v3/host_sets?limit=$Limit" -Headers $header).data.entries) | ? {$_.name -eq "$Name"} | select _id

    # Gets info on a single Host Set given the HostSetID
    If($Name -and $HSID){
        $getHostSet = Invoke-RestMethod -Uri "$URL/hx/api/v3/host_sets/$($HSID._id)?limit=$Limit" -Headers $header -Method Get
        $getHostSet.data
        }
    # Gets info on all Host Sets
    Else{
        $getHostSet = Invoke-RestMethod -Uri "$URL/hx/api/v3/host_sets?limit=$Limit" -Headers $header -Method Get
        $getHostSet.data
        }
    }

# Delete a Host Set by ID Request
Function HX-Del-HostSet {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Name
        )
    
    # Required Header information
    $header = @{
        "X-FeApi-Token" = "$Token"
        }

    # Gets the ID of the Host Set using the Name info provided
    $HSID = ((HX-Get-HostSet -URL $URL -Token $Token).entries) |Where-Object {$_.name -eq "$Name"} | select _id

    If($HSID){
        # Deletes Host Set by ID
        $delHostSet = Invoke-RestMethod -Method Delete -Uri "$URL/hx/api/v3/host_sets/$($HSID._id)" -Headers $header
        
        $delHostSet
        }
    Else{Write-Error "Host Set Name not found"}
}

# List of Hosts Within a Host Set Request
Function HX-Get-HostSetMembers {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [string]$Limit='35000'
        )

    # Required Header information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
     # Gets the ID of the Host Set using the Name info provided
    $HSID = ((HX-Get-HostSet -URL $URL -Token $Token).entries) |Where-Object {$_.name -eq "$Name"} | select _id

    If($HSID){
        # Gets info on hosts within a hostset given the HostSetID
        $getHostSetMembers = Invoke-RestMethod -Uri "$URL/hx/api/v3/host_sets/$($HSID._id)/hosts?limit=$Limit" -Headers $header -Method Get
        $getHostSetMembers.data
        }
    Else{Write-Error "Host Set Name not found"}
    }



#----------#
#  Search  #
#----------#

# New Search Request
# POST https://HX_IP_address:port_number/hx/api/v3/searches

# List of Searches for All Hosts
# GET https://HX_IP_address:port_number/hx/api/v3/searches

# List of Search Information Request
# GET https://HX_IP_address:port_number/hx/api/v3/searches/counts

# Search by ID Request
# GET https://HX_IP_address:port_number/hx/api/v3/searches/:id

# Delete Search by ID Request
# DELETE https://HX_IP_address:port_number/hx/api/v3/searches/:id

# Stop a Search Request
# POST $URL/hx/api/v3/searches/:id/actions/action

# List of Hosts and States for a Search Request
# GET https://HX_IP_address:port_number/hx/api/v3/searches/:id/hosts

# List of Hosts Skipped by a Search Request
# GET https://HX_IP_address:port_number/hx/api/v3/searches/:id/skipped_hosts

# List of Search Results for a Host Request
# GET $URL/hx/api/v3/searches/:id/hosts/:agent_id

# List of Hosts and Results for a Search Request
# GET https://HX_IP_address:port_number/hx/api/v3/searches/:id/results

# List of Hosts for a Grid Row Request
# GET $URL/hx/api/v3/searches/:id/results/:row_id/hosts


 
#--------------#
#  Indicators  #
#--------------#
 
# Get information on existing IOC
Function HX-Get-IOC {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$Category,
        [string]$Indicator
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Gets information about a specific indicator - If Category and ID are supplied
    If($Indicator -and $Category){
        $IOCs = Invoke-RestMethod -Uri "$URL/hx/api/v3/indicators/$Category/$Indicator" -Headers $header -Method Get
        $IOCs.data
        }
    # Gets a list of Indicators within a category - If Category is supplied
    elseIf($Category){
        $IOCs = Invoke-RestMethod -Uri "$URL/hx/api/v3/indicators/$Category" -Headers $header -Method Get
        $IOCs.data
        }
    # Lists all indicators
    else{
        $IOCs = Invoke-RestMethod -Uri "$URL/hx/api/v3/indicators?limit=1000" -Headers $header -Method Get
        $IOCs.data
        }
    }
 
# Create New IOC by Name
Function HX-Add-IOC {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [string]$Category = "custom",
        [string]$Description = "Custom IOC Created via API",
        [string[]]$Platform = ("win","osx"),
        [string]$CreateText = "API_Admin"
        #[string[]]$PresenceConditions,
        #[string[]]$ExecutionConditions
        )

    # Required Header info
    $header = @{
        "X-FeApi-Token" = "$Token"
        }
   
    # Creates Body for request
    $Body =[PSCustomObject]@{
        create_text = "$CreateText"
        description = "$Description"
        platforms = @($Platform)
        }
    # Converts Body to json
    $json = $Body | ConvertTo-Json -Depth 3
    
    # Creates new IOC
    $createIOC = irm -Uri "$URL/hx/api/v3/indicators/$Category/$Name" -Headers $header -Body $json -Method Put -ContentType 'application/json' 
    $createIOC.data
    }


# New Indicator Condition with Defined Type Request on page 321
# POST https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/conditions/:type
Function HX-Add-IOC-Condition {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        #[Parameter(Mandatory=$true)]
        #[string]$Conditions,
        [Parameter(Mandatory=$true)]
        [ValidateSet('presence','execution')]
        [string]$Type,
        [string]$Category = "custom"
        )

    # Required Header info
    $header = @{
        "X-FeApi-Token" = "$Token"
        }

    # Creates Body for request
    $Body = (Get-Content -Path (openFile -Title "Select File Containing IOC Test Conditions in JSON format."))
    
    # Creates new IOC
    $createIOC = irm -Uri "$URL/hx/api/v3/indicators/$Category/$Name/conditions/$type" -Headers $header -Body $Body -Method Post -ContentType 'application/json' 
    $createIOC.data
    }

# Partially Update an Indicator Request on page 325
# PATCH https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator

# Move an Indicator Request on page 330
# MOVE https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator

# Delete an Indicator by Name Request on page 334
# DELETE https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator

# Bulk Replace Conditions Request
# PUT https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/conditions

# Bulk Append Conditions Request
# PATCH https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/conditions

# List of Conditions for an Indicator Request
Function HX-Get-IOC-Condition {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$Category,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [ValidateSet('presence','execution')]
        [string]$Type
        )

    # Required Header information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    If($type){
        $getConditions = irm -Uri "$URL/hx/api/v3/indicators/$Category/$Name/conditions/$type`?limit=100" -Headers $header
        $getConditions.data
        }
    Else{
        $getConditions = irm -Uri "$URL/hx/api/v3/indicators/$Category/$Name/conditions?limit=100" -Headers $header
        $getConditions.data
        }
    }

# List of Conditions for an Indicator by Type Request
# GET https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/conditions/:type

# List of Source Alerts for an Indicator Request
# GET https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/source_alerts

# New Source Alert Request
# POST https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/source_alerts



#--------------#
#  Conditions  #
#--------------#

# New Condition Request
# POST https://HX_IP_address:port_number/hx/api/v3/conditions

# Enable a Condition by ID Request
# PATCH https://HX_IP_address:port_number/hx/api/v3/conditions/:id

# Condition by ID Request
# GET https://HX_IP_address:port_number/hx/api/v3/conditions/:id

# List of Conditions for All Hosts Request
# GET https://HX_IP_address:port_number/hx/api/v3/conditions

# List of Indicators That Use a Condition Request
# GET $URL/hx/api/v3/conditions/:condition_id/indicators



#------------------------#
#  Indicator Categories  #
#------------------------#

# List of Indicator Categories Request
# GET https://HX_IP_address:port_number/hx/api/v3/indicator_categories

# Indicator Category by Name Request
# GET https://HX_IP_address:port_number/hx/api/v3/indicator_categories/:category

# New Indicator Category with Predefined Category Name Request
# PUT https://HX_IP_address:port_number/hx/api/v3/indicator_categories/:category

# Partially Update an Indicator Category Request
# PATCH https://HX_IP_address:port_number/hx/api/v3/indicator_categories/:category

# Move an Indicator Category Request
# MOVE https://HX_IP_address:port_number/hx/api/v3/indicator_categories/:category

# Delete an Indicator Category by Name Request
# DELETE https://HX_IP_address:port_number/hx/api/v3/indicator_categories/:category



#----------#
#  Alerts  #
#----------#

# Alert by ID Request
# GET https://HX_IP_address:port_number/hx/api/v3/alerts/:id

# List of Alerts for All Hosts Request
# GET https://HX_IP_address:port_number/hx/api/v3/alerts

# Filtered List of Alerts for All Hosts Request
# POST https://HX_IP_address:port_number/hx/api/v3/alerts/filter

# Alert Suppression by ID Request
# DELETE https://HX_IP_address:port_number/hx/api/v3/alerts/:id



#-----------------#
#  Source Alerts  #
#-----------------#

# Source Alert by ID Request on the next page
# GET https://HX_IP_address:port_number/hx/api/v3/source_alerts/:id

# List of Source Alerts for All Hosts Request on page 507
# GET https://HX_IP_address:port_number/hx/api/v3/source_alerts/

# List of Alerted Hosts by Source Alert Request on page 515
# GET https://HX_IP_address:port_number/hx/api/v3/source_alerts/:id/alerted_hosts

# List of Alerts by Source Alert Request on page 521
# GET https://HX_IP_address:port_number/hx/api/v3/source_alerts/:id/alerts

# Update Source Alert by ID Request on page 533
# PATCH https://HX_IP_address:port_number/hx/api/v3/source_alerts/:id

# Source Alert Suppression by ID Request on page 537
# DELETE https://HX_IP_address:port_number/hx/api/v3/source_alerts/:id



#----------------#
#  Acquisitions  #
#----------------#

# List of File Acquisitions for All Hosts Request on page 545
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/files

# File Acquisition by ID Request on page 556
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/files/:id

# File Acquisition Package by ID Request on page 561
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/files/:id.zip

# Delete File Acquisition by ID Request on page 566
# DELETE https://HX_IP_address:port_number/hx/api/v3/acqs/files/:id

# List of Triage Acquisitions for All Hosts Request on page 570
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/triages

# Triage Acquisition by ID Request on page 581
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/triages/:id

# Triage Collection by ID Request on page 587
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/triages/:id.mans

# Delete Triage Acquisition by ID Request on page 591
# DELETE https://HX_IP_address:port_number/hx/api/v3/acqs/triages/:id

# New Bulk Acquisition Request on page 595
# POST https://HX_IP_address:port_number/hx/api/v3/acqs/bulk

# List of Bulk Acquisitions for All Hosts Request on page 608
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/bulk

# Bulk Acquisition by ID Request on page 622
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id

# Change the State of a Bulk Acquisition Request on page 626
# POST https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/actions/:action

# Refresh a Host’s Data in a Bulk Acquisition Request on page 631
# POST https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/hosts/:agent_id/actions/:action

# Delete Bulk Acquisition by ID Request on page 635
# DELETE https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id

# Bulk Acquisition Package by Host Request on page 639
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/hosts/:agent_id.zip

# Delete Bulk Acquisition Package by Host Request on page 642
# DELETE https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/hosts/:agent_id.zip

# List of Hosts for a Bulk Acquisition Request on page 645
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/hosts

# List of Hosts Skipped by a Bulk Acquisition Request on page 657
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/skipped_hosts

# Bulk Acquisition Status by Host Request on page 662
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/hosts/:agent_id

# Add a Host to a Bulk Acquisition Request on page 667
# PUT https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/hosts/:agent_id

# Remove a Host from a Bulk Acquisition Request on page 671
# DELETE https://HX_IP_address:port_number/hx/api/v3/acqs/bulk/:id/hosts/:agent_id

# Data Acquisition by ID Request on page 674
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/live/:id

# Data Collection by ID Request on page 677
# GET https://HX_IP_address:port_number/hx/api/v3/acqs/live/:id.mans

# Delete Data Acquisition by ID Request on page 680
# DELETE https://HX_IP_address:port_number/hx/api/v3/acqs/live/:id



#-----------#
#  Scripts  #
#-----------#

# Get list of Scripts for all hosts
Function HX-Get-Script {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$ScriptID
        )

    # Required Header Information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Gets info on a single script if the ID is provided
    If($SriptID){
        $getScript = Invoke-RestMethod -Uri "$URL/hx/api/v3/scripts/$SriptID" -Headers $header -Method Get
        $getScript.data
        }
    # Gets info on all scripts when SriptID is not provided
    Else{
        $getScript = Invoke-RestMethod -Uri "$URL/hx/api/v3/scripts?limit=100" -Headers $header -Method Get
        $getScript.data
        }
    }

# Script Content by ID Request
# GET https://HX_IP_address:port_number/hx/api/v3/scripts/:id.xml

# Script Content for All Hosts Request
# GET https://HX_IP_address:port_number/hx/api/v3/scripts.zip


 
#---------------#
#  Containment  #
#---------------#
 
# Request Containment of host by ID
Function HX-Contain-Request {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$AgentID
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Requests containment on a host given it's AgentID
    $ReqContain = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID/containment" -Headers $header -Method Post
    $ReqContain
    }
 
# Approve Containment for a host
Function HX-Contain-Approve {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$AgentID
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Approves Containment of a host given it's AgentID and a request exists
    $ApproveContain = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID/containment" -Headers $header -Method Patch
    $ApproveContain
    }
 
# Cancel Containment for a host
Function HX-Contain-Cancel {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$AgentID
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Cancels containment of a host
    $CancelContain = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID/containment" -Headers $header -Method Delete
    $CancelContain
    }

# Get Containment State of a host
Function HX-Get-Containment {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$AgentID
        )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    
    # Gets Containment state of a single host if AgentID is supplied
    If($AgentID){
        $getContain = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID/containment" -Headers $header -Method Get
        $getContain
        }
    # Gets Containment state of all hosts if AgentID is not supplied
    Else{
        $getContain = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/containment_states" -Headers $header -Method Get
        $getContain
        }
    }



#---------------------------------#
#  Custom Configuration Channels  #
#---------------------------------#

# List of Configuration Channels Request on page 732
# GET https://HX_IP_address:port_number/hx/api/v3/host_policies/channels

# New Configuration Channel Request on page 739
# POST https://HX_IP_address:port_number/hx/api/v3/host_policies/channels

# Configuration Channel by ID Request on page 743
# GET https://HX_IP_address:port_number/hx/api/v3/host_policies/channels/:id

# Update a Configuration Channel Request on page 747
# PATCH https://HX_IP_address:port_number/hx/api/v3/host_policies/channels/:id

# Delete a Configuration Channel Request on page 751
# DELETE https://HX_IP_address:port_number/hx/api/v3/host_policies/channels/:id

# Configuration by ID Request on page 753
# GET https://HX_IP_address:port_number/hx/api/v3/host_policies/channels/:id.json

# Update the Configuration Request on page 756
# PUT https://HX_IP_address:port_number/hx/api/v3/host_policies/channels/:id.json

# List of Hosts for a Configuration Channel Request on page 760
# GET https://HX_IP_address:port_number/hx/api/v3/host_policies/channels/:id/hosts



#---------#
#  Misc.  #
#---------#

# Opens Dialog window to select a file
Function openFile($initialDirectory,$Title)
{ 
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
    Out-Null

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Title = "$Title"
    $OpenFileDialog.initialDirectory = $initialDirectory
    $OpenFileDialog.filter = "All files (*.*)|*.*"
    $OpenFileDialog.ShowDialog() | Out-Null
    $OpenFileDialog.ShowHelp = $true
    $OpenFileDialog.filename
}

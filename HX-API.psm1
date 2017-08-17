<#
 
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
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL
        )
 
    # Prompts for and processes API user creds  
    $c = Get-Credential
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
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token
        )
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    # Deletes user token 
    $apiLogOff = Invoke-WebRequest -Uri "$URL/hx/api/v3/token" -Headers $header -Method Delete
    $apiLogOff
    }
 
 
 
#-----------#
#  Version  #
#-----------#

# Returns a list of All hosts in FireEye
Function HX-Get-Version {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token
        )
   
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Gets HX Version
    $hxVersion = Invoke-RestMethod -Uri "$URL/hx/api/v3/version" -Headers $header -Method Get
    $hxVersion
    }
 
 
 
#--------------------#
#  Host Information  #
#--------------------#

# Returns a list of All hosts in FireEye
Function HX-Get-AllHosts {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token
        )
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)
    $FireEyeHosts = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts?limit=35000" -Headers $header -Method Get
    $FireEyeHosts
    }

# Searches HX for a host
Function HX-Search-Hosts {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
        [string]$Search
        )
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Searches HX for a host that matches the search object
    $FireEyeSearch = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts?search=$Search" -Headers $header -Method Get 
    $FireEyeSearch
    }

# Delete Host based off Agent ID
Function HX-Delete-Host {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
        [string]$AgentID
        )
   
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Deletes a host from HX using it's AgentID
    $DeleteHost = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID" -Headers $header -Method Delete
    $DeleteHost.StatusCode
    }

# Get Agent configuration for a host
Function HX-Get-AgentConf {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
        [string]$AgentID
        )
   
    # Required Header information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Gets agent config for a given AgentID
    $AgentConf = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID/configuration/actual.json" -Headers $header -Method Get
    $AgentConf
    }


 
#-------------#
#  Host Sets  #
#-------------#
 
# New Static Host Set Request
# POST https://HX_IP_address:port_number/hx/api/v3/host_sets/static
Function HX-Add-HostSet-Static {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
        [string]$Name,
        [string[]]$AddHosts
        )
   
    # Sets up the Body to convert to json
    $Body =@{
        name = "$Name"
        changes = @(
            @{
                command = "change";
                add = @($AddHosts);
                #remove = []
            }
        )
    }
    $json = $Body | ConvertTo-Json #-Compress
    write-host $json
    # Required Header information
    $header = @{
        "Accept" = "application/json"
        #"Content-Type" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Adds Static Host Set
    $addHostSet = irm -Method Post -Uri "$URL/hx/api/v3/host_sets/static" -Headers $header -Body $json -ContentType 'application/json'
    $addHostSet
    }
 
# New Dynamic Host Set Request
# POST https://HX_IP_address:port_number/hx/api/v3/host_sets/dynamic
 
# Update a Static Host Set Request
# PUT https://HX_IP_address:port_number/hx/api/v3/host_sets/static:id
 
# Update a Dynamic Host Set Request
# PUT https://HX_IP_address:port_number/hx/api/v3/host_sets/dynamic:id
 
# List of Host Sets or info on a single Host Set if ID is provided
Function HX-Get-HostSet {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
        [string]$HostSetID
        )
   
    # Required Header information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Gets info on a single Host Set given the HostSetID
    If($HostSetID){
        $getHostSet = Invoke-RestMethod -Uri "$URL/hx/api/v3/host_sets/$HostSetID`?limit=100" -Headers $header -Method Get
        $getHostSet
        }
    # Gets info on all Host Sets
    Else{
        $getHostSet = Invoke-RestMethod -Uri "$URL/hx/api/v3/host_sets?limit=100" -Headers $header -Method Get
        $getHostSet
        }
    }
 
# Delete a Host Set by ID Request
# DELETE https://HX_IP_address:port_number/hx/api/v3/host_sets/:id
 
# List of Hosts Within a Host Set Request
Function HX-Get-HostSetMembers {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
        [string]$HostSetID
        )
 
    # Required Header information
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    # Gets info on hosts within a hostset given the HostSetID
    $getHostSetMembers = Invoke-RestMethod -Uri "$URL/hx/api/v3/host_sets/$HostSetID/hosts?limit=35000" -Headers $header -Method Get
    $getHostSetMembers  
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
Function HX-Get-Indicator {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
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
        $IOCs
        }
    # Gets a list of Indicators within a category - If Category is supplied
    elseIf($Category){
        $IOCs = Invoke-RestMethod -Uri "$URL/hx/api/v3/indicators/$Category" -Headers $header -Method Get
        $IOCs
        }
    # Lists all indicators
    else{
        $IOCs = Invoke-RestMethod -Uri "$URL/hx/api/v3/indicators" -Headers $header -Method Get
        $IOCs
        }
    }

# Create New IOCs  ###  INCOMPLETE  ###
Function HX-Add-Indicator {
    # Defining Parameters
    Param(
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [string]$Category,
        [string]$Indicator,
        [Parameter(Mandatory=$TRUE)]
        [string]$Body
        )
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
  
    $createIOC = Invoke-RestMethod -Uri "$URL/hx/api/v3/indicators" -Headers $header -Body $Body -Method Post
    }

# New Indicator Request on page 302
# POST https://HX_IP_address:port_number/hx/api/v3/indicators/:category
 
# New Indicator with Predefined Name Request on page 306
# PUT $URL/hx/api/v3/indicators/:category/:indicator
 
# New Indicator Condition with Defined Type Request on page 321
# POST https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/conditions/:type
 
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
# GET https://HX_IP_address:port_number/hx/api/v3/indicators/:category/:indicator/conditions
 
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
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
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
        $getScript
        }
    # Gets info on all scripts when SriptID is not provided
    Else{
        $getScript = Invoke-RestMethod -Uri "$URL/hx/api/v3/scripts?limit=100" -Headers $header -Method Get
        $getScript
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
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
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
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
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
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
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
        [Parameter(Mandatory=$TRUE)]
        [string]$URL,
        [Parameter(Mandatory=$TRUE)]
        [string]$Token,
        [Parameter(Mandatory=$TRUE)]
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
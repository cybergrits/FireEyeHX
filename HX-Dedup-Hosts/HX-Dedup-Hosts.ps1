<#
.SYNOPSIS
    Removes hosts in HX with duplicate hostnames.
 
.DESCRIPTION
    This script will check HX for hosts that have the same hostname.
    It will sort and identify the host with the most recent last_poll_timestamp
    and delete the rest from HX.
 
.PARAMETER
    Server: IP address or URL of the HX server
 
    Port: Port number the HX server is listening on
 
.EXAMPLE
    C:\> HX-Dedup-Hosts.ps1 -Server x.x.x.x -Port ####
 
.NOTES   
    Author: Jeff Williams
    Email: jeff@cybergrits.com
    Date: 8/1/2017
#>
 
 

param(
    [string]$Server,
    [string]$Port
    )
 
$FireEyeUrl = "https://$Server"+":$Port"
$timestamp = Get-Date -Format yyyyMMdd-HHmm
 
 
Function saveFile($initialDirectory,$Title,$SaveAs){
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
    Out-Null
 
    $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $SaveFileDialog.Title = "$Title"
    $SaveFileDialog.initialDirectory = $initialDirectory
    $SaveFileDialog.FileName = "$SaveAs"
    $SaveFileDialog.filter = "All files (*.*)|*.*"
    $SaveFileDialog.ShowDialog() | Out-Null
    $SaveFileDialog.ShowHelp = $true
    $SaveFileDialog.filename
}
 
 
Function Ignore-SelfSignedCerts {
# Enables the use of Self Signed Certs
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
 
 
Function HX-Auth {
# Authenticates to the HX Server and returns a user Token
 
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
    $gettoken = Invoke-WebRequest -Uri "$FireEyeUrl/hx/api/v3/token" -Headers $header -Method Get
 
    $token = $gettoken.Headers.'X-FeApi-Token'
    $token
 
    }
 
 
Function HX-DeAuth($Token) {
# Logs off API user of supplied Token
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    $apiLogOff = Invoke-WebRequest -Uri "$FireEyeUrl/hx/api/v3/token" -Headers $header -Method Delete
 
    $apiLogOff
 
    }
 
 
Function HX-Get-Hosts($Token) {
# Gets Info for All hosts in HX
 
    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
    # Gets info on all hosts in HX (Notice the "...?limit=35000" and
    # increase/decrease depending on number of agents in HX)    #>
    $FireEyeHosts = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/hosts?limit=35000" -Headers $header -Method Get
 
    $FireEyeHosts
 
    }
 
 
Function HX-Delete-Host($AgentID,$Token){
# Delete Host based off Agent ID
 
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    $DeleteHost = Invoke-RestMethod -Uri "$FireEyeUrl/hx/api/v3/hosts/$AgentID" -Headers $header -Method Delete
       
    $DeleteHost.StatusCode
    }
 
 
# Execute Ignore Self Signed Certs
Ignore-SelfSignedCerts
 
# Logs into the HX server and gets a user token
$Token = HX-Auth
 
# Gets Host info from the HX server
$hxGet = HX-Get-Hosts -Token $Token
 
# Creates and Organizes a usful host list from the data recieved
Write-Host "Getting Host info from HX" -ForegroundColor Cyan
$hosts = $hxGet.data.entries | select _id,agent_version,hostname,last_poll_timestamp |
    Sort-Object -Property hostname,last_poll_timestamp -Descending
 
# Identifies unique hosts   
$uniqueHosts = $hosts | Sort-Object -Unique hostname -Descending
 
# Creates a list of just the duplicate hosts
$rhosts= @()
$c1 = 0
Foreach($h in $hosts){
   
    $c1++
    Write-Progress -Activity "Identifying Duplicates" -Status "Processing" -PercentComplete (($c1 / $hosts.Count)*100)
 
    if($h -notin $uniqueHosts){
        $rhosts += $h
        }
   
    }
 
 
# Verifies that you would like to remove the hosts from HX
# and saves a log file if you continue.
Write-Host "You are about to remove $($rhosts.Count) hosts from HX." -ForegroundColor Red
$continue = Read-Host "Do you wish to continue? (y/n): "
 
if($continue -ieq 'y'){
    # Removes hosts
    $c2 = 0
    Foreach($id in $rhosts._id){
   
        $c2++
        Write-Progress -Activity "Removing Hosts from HX" -Status "Processing" -PercentComplete (($c2 / $rhosts.Count)*100)
 
        HX-Delete-Host -AgentID $id -Token $Token
 
        }
    Write-Host "Removed $($rhosts.Count) hosts from HX" -ForegroundColor Green
   
    # Saves Log File
    $sfile = saveFile -Title "Save Log File As" -SaveAs "HostsRemovedFromHX-$timestamp.csv"
    $rhosts | Export-Csv -Path $sfile -NoTypeInformation
    }
Else{
    Write-Host "Process Aborted: $timestamp" -ForegroundColor Red
    }
 
# Logs out of HX
HX-DeAuth -Token $Token

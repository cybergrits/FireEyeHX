<#
.SYSNOPSIS
    Removes hosts in HX with duplicate hostnames.
 
.DESCRIPTION
    This script will check HX for hosts that have the same hostname.
    It will sort and identify the host with the most recent last_poll_timestamp
    and delete the rest from HX.
 
.PARAMETERS
    Server: IP address or URL of the HX server
 
    Port: Port number the HX server is listening on
 
.EXAMPLE
    C:\> HX-Dedup-Hosts.ps1 -Server x.x.x.x-Port ####
 
.NOTES   
    Author: Jeff Williams
    Email: jeff@cybergrits.com
    Date: 8/1/2017
#>
 
 
 
param(
    [parameter(Mandatory=$true)]
    [string]$Server,
    [string]$Port = "3000"
    )
 
$Url = "https://$Server"+":$Port"
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
    # Define Parameters
    Param(
        [Parameter(Mandatory)]
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
    $gettoken = Invoke-WebRequest -Uri "$Url/hx/api/v3/token" -Headers $header -Method Get
 
    $token = $gettoken.Headers.'X-FeApi-Token'
    $token
}
 
 
Function HX-DeAuth {
# Logs off API user of supplied Token
    #Define Parameters
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
    if($apiLogOff.StatusCode -eq "204"){Write-Host "User Successfully Logged Off" -ForegroundColor Cyan}     
}
 
 
Function HX-Get-Hosts {
# Gets Info for All hosts in HX
    #Define Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [string]$Limit='65000'
    )

    # Required Header info
    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
    }
    # Gets info on all hosts in HX 
    $FireEyeHosts = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts?limit=$Limit" -Headers $header -Method Get
    $FireEyeHosts
 }
 
 
Function HX-Delete-Host{
# Delete Host based off Agent ID
    #Define Parameters
    Param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [Parameter(Mandatory=$true)]
        [string]$Token,
        [Parameter(Mandatory=$true)]
        [string]$AgentID
    )

    $header = @{
        "Accept" = "application/json"
        "X-FeApi-Token" = "$Token"
        }
   
    $DeleteHost = Invoke-RestMethod -Uri "$URL/hx/api/v3/hosts/$AgentID" -Headers $header -Method Delete
       
    $DeleteHost.StatusCode
    }
 
 
# Execute Ignore Self Signed Certs
Ignore-SelfSignedCerts
 
# Logs into the HX server and gets a user token
$Token = HX-Auth -Url $Url
 
# Gets Host info from the HX server
write-host "Getting Host information from Endpoint Security" -ForegroundColor Cyan
$hxGet = (HX-Get-Hosts -Token $Token -URL $Url).data.entries | select _id,hostname,last_audit_timestamp
Write-Host "$($hxGet.Count) Hosts in HX `n" -ForegroundColor Green

# Formats Last audit timestamp to a number
Write-Host "Formatting Data" -ForegroundColor Cyan
$hxGet | foreach {$_.last_audit_timestamp = $_.last_audit_timestamp -replace"-","" -replace"T","" -replace".000Z",""}
$hxGet | foreach {$_.last_audit_timestamp = $_.last_audit_timestamp.ToInt64($null)}

# Finds and Groups Duplicate Hostnames
Write-host "Identifing hosts with duplicate hostname" -ForegroundColor Cyan
$hg=$hxGet | Group-Object -Property hostname | where -FilterScript {$_.count -gt 1}

# Identifies latest agent based off last_audit_timestamp
$latestAgent = @()
$duplicateHosts=@()

foreach($h in $hg){
    # Finds latest timestamp
    $latestTimestamp = ($h.Group | measure -Maximum -Property last_audit_timestamp).Maximum

    # Places Host in proper group
    foreach($d in $h.Group){
        if($d.last_audit_timestamp -eq $latestTimestamp){
            $latestAgent += $d
        }
        Else{$duplicateHosts += $d}
    }
}
$newCount=$latestAgent.count
$dupCount=$duplicateHosts.Count
Write-Host "Found $newCount hosts with duplicate agents" -ForegroundColor Green
Write-Host "Identified $dupCount duplicate hosts `n" -ForegroundColor Yellow

# Verifies that you would like to remove the dups from HX
# and saves a log file if you continue
Write-Host "You are about to remove $dupCount hosts from HX." -ForegroundColor Red
$continue = Read-Host "Do you wish to continue? (y/n)"
$timestamp = Get-Date -Format yyyyMMdd-HHmm

if($continue -eq 'y'){
    # Removes hosts
    $c1=0
    foreach($id in $duplicateHosts._id){
        $c1++
        Write-Progress -Activity "Removing hosts from HX" -Status "Processing $c1 of $dupCount" -PercentComplete (($c1/$dupCount)*100)

        HX-Delete-Host -AgentID $id -URL $Url -Token $Token
    }
    Write-Host "Removed $dupCount hosts from HX" -ForegroundColor Cyan

    $logFile = saveFile -Title "Save Log File As" -SaveAs "HostsDeleted-HX-$timestamp.csv"
    $duplicateHosts | Export-Csv -Path $logFile -NoTypeInformation
}
Else{
    # Saves all logs
    $logFile = saveFile -Title "Save Log File As" -SaveAs "HostsFrom-HX-"
    $hg.Group | Export-Csv -Path "$logFile-RawExport.csv" -NoTypeInformation
    $latestAgent | Export-Csv -Path "$logFile-LatestAgent.csv" -NoTypeInformation
    $duplicateHosts | Export-Csv -Path "$logFile-Duplicates.csv" -NoTypeInformation
    Write-Host "Process Aborted: $timestamp" -ForegroundColor Red
}

# Closes API session with HX
HX-DeAuth -URL $Url -Token $Token

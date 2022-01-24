#Avoid TLS trust relationship error
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#Initialize credentials
#$AESkey = New-Object Byte[] 32
#[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESkey)
#Read-Host -AsSecureString | ConvertFrom-SecureString -key $AESkey | Out-File 'C:\Users\myuser\Documents\04.Tenable.sc\scripts\creds\encrypt.xml'
#$AESkey | Out-File 'C:\Users\myuser\Documents\04.Tenable.sc\scripts\creds\aeskey.key'


$secCenterURL = "https://192.168.1.111"

#PREPARE SESSION TO IMPORT TO SECURITYCENTER
#Retrieve AES key and encrypted password.
$key = Get-Content 'C:\Users\myuser\Documents\04.Tenable.sc\scripts\creds\aeskey.key'
$username = "api"
$password = Get-Content 'C:\Users\myuser\Documents\04.Tenable.sc\scripts\creds\encrypt.xml' | ConvertTo-SecureString -Key $key
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password
#Build login data
$login = New-Object PSObject 
$login | Add-Member -MemberType NoteProperty -Name username -Value $MyCredential.UserName
$login | Add-Member -MemberType NoteProperty -Name password -Value $MyCredential.GetNetworkCredential().password
$Data = (ConvertTo-Json -Compress $login)
#Get token and cookie
$ret = Invoke-WebRequest -Uri $secCenterURL/rest/token -Method Post -Body $Data -UseBasicParsing -SessionVariable sv
$token = (ConvertFrom-Json $ret.Content).response.token


#set TLS to 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Get token and cookie
#$ret = Invoke-WebRequest -Uri $secCenterURL/rest/token -Method Post -Body $Data -UseBasicParsing -SessionVariable sv

#$token = (ConvertFrom-Json $ret.Content).response.token
#Get all scanresults from SecurityCenter
#$ret = Invoke-WebRequest -Uri " $secCenterURL/rest/scanResult?fields=name,status,finishTime,repository " -Method Get -Headers @{"X-SecurityCenter"="$token"} -WebSession $sv

#Get Assets
#Fields
#name, id, type(combination, dynamic, static)
#typeFields = Asset definition (IPs, rules, or other assets for combination)
$ret = Invoke-WebRequest -Uri " $secCenterURL/rest/asset?fields=name,id,type,typeFields " -Method Get -Headers @{"X-SecurityCenter"="$token"} -WebSession $sv


# Store assets for further processing
$assets = (ConvertFrom-Json $ret.Content)

#Get Scans
$ret = Invoke-WebRequest -Uri " $secCenterURL/rest/scan?fields=name,id,assets " -Method Get -Headers @{"X-SecurityCenter"="$token"} -WebSession $sv

# Store scans for further processing
$scans = (ConvertFrom-Json $ret.Content)

#Get all dynamic assets
foreach ($asset in $assets.response.usable) {
    if (($asset.type -eq "Dynamic") ) {
		Write-Host "$($asset.name) - $($asset.id)"
    }
}

#Get assets from a scan name
foreach ($scan in $scans.response.usable) {
    if ($scan.name -eq "Scan Name") {
    Write-Host " $($scan.assets.name)"  
   # Write-Host "$($scan.assets.name)"
    }
}

#Find scan which uses asset by ID
$id = "89"
if ( $scans.assets.id.Contains($id) ) {
    Write-host True
}


#Get all assets of type combination
$combinationAssets = @()
foreach ( $asset in $assets.response.usable ) {
    if ( $asset.type -eq "Combination" ) {
        $combinationAssets += $asset
    }
}

#Save in array all assets "Dynamic" or "Combination" that are present in an active scan
$inuse = @()
foreach ( $asset in $assets.response.usable ) {
    if ( ($asset.type -eq "Dynamic") -or ($asset.type -eq "Combination") ) {
        if ($asset.id -in $scans.response.usable.assets.id) {
            $inuse += $asset
        }
    }
}

foreach ( $asset in $inuse) {
    $asset
}

#Save in array all assets not used in any scan
#Be careful with combination scans, they have dynamic assets nested
$NOTinuse = @()
foreach ( $asset in $assets.response.usable ) {
    #if ( ($asset.type -eq "Dynamic") -or ($asset.type -eq "Combination") ) {
        if ($asset.id -notin $scans.response.usable.assets.id) {
            $NOTinuse += $asset
        }
    #}
}

#Get all combinatin assets
foreach ( $asset in $assets.response.usable ) {
    if ( ($asset.type -eq "Combination") ) {
        $asset.id
    }
}

#Get all fields for an asset by ID
$ret = Invoke-WebRequest -Uri " $secCenterURL/rest/asset/65 " -Method Get -Headers @{"X-SecurityCenter"="$token"} -WebSession $sv

$combination = (ConvertFrom-Json $ret.Content)

#Expand in JSON all assets combined in this combination asset
$combinationJSON = $combination.response.typeFields | ConvertTo-Json -Depth 100

#Expand all fields for assets in JSON format
$assetsJSON = $assets.response.usable | ConvertTo-Json -Depth 100

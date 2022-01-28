## Avoid TLS errors
#Avoid TLS trust relationship error
# Depending on environment, you may need this
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

# Same for TLS to 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Prepare login credentials from stored password 
# We retrieve the key and generate a secure string with the password in encrypt.xml
# Use a read only user if you don't need to make changes through the API.
$key = Get-Content 'C:\creds\aeskey.key'
$username = "api_user"
$password = Get-Content 'C:\creds\encrypt.xml' | ConvertTo-SecureString -Key $key
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $username, $password

# Create a PSObject to store all the login details
# Build login data
$login = New-Object PSObject 
$login | Add-Member -MemberType NoteProperty -Name username -Value $MyCredential.UserName
$login | Add-Member -MemberType NoteProperty -Name password -Value $MyCredential.GetNetworkCredential().password
$Data = (ConvertTo-Json -Compress $login)
$tenableSC = "https://192.168.1.111"

# Get the token and cookie from the server for all future API requests in this session
# With the new credential object, we can authenticate to the Tenable.sc server and get the token and cookie (session variable)
$request = Invoke-WebRequest -Uri $tenableSC/rest/token -Method Post -Body $Data -UseBasicParsing -SessionVariable sv
$token = (ConvertFrom-Json $request.Content).response.token

# We reuse the $token and $sv variables for all subsequent requests.

# get all the assets and follwing fields:
# name, id, type(combination, dynamic, static)
$request = Invoke-WebRequest -Uri " $tenableSC/rest/asset?fields=name,id,type,typeFields " -Method Get -Headers @{"X-SecurityCenter"="$token"} -WebSession $sv
$assets = (ConvertFrom-Json $request.Content)
$assets = $assets.response.usable

# get the active scans currently configured with the following fields:
# name, id, assets
$request = Invoke-WebRequest -Uri " $tenableSC/rest/scan?fields=name,id,assets " -Method Get -Headers @{"X-SecurityCenter"="$token"} -WebSession $sv
$scans = (ConvertFrom-Json $request.Content)
$scans = $scans.response.usable



# Now let's see which Dynamic assets are being used by any scan:
$inuse = @()
foreach ( $asset in $assets ) {
    if ($asset.type -eq "Dynamic") {
        if ($asset.id -in $scans.assets.id) {
            $inuse += $asset
        }
    }
}

# We have saved all assets currently being used by any scan in our server in the variable 'inuse'
# Those are the ones we shouldn't remove as it would break a scan.

#Save in array all assets not used in any scan
$NOTinuse = @()
foreach ( $asset in $assets ) {
    if ($asset.type -eq "Dynamic")  {
        if ($asset.id -notin $scans.assets.id) {
            $NOTinuse += $asset
        }
    }
}


# Now, all the assets in $NOTinuse are not being used by any scan
# IMPORTANT: do a sanity check first to be sure the output is correct
# then you could mass delete them with the following

foreach ($asset in $NOTinuse) {
    $request = Invoke-WebRequest -Uri " $tenableSC/rest/asset/$asset.id " -Method Delete -Headers @{"X-SecurityCenter"="$token"} -WebSession $sv
}


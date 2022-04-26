# Generate authentication headers
$accessKey = 'ACCESS_KEY_HERE'
$secretKey = 'SECRET_KEY_HERE'

$headers = @{}
$headers.Add("x-apikey", "accessKey=$accessKey;secretKey=$secretKey")

$scURL = 'https://192.168.23.12'

#Get all plugins with CVEs
$result = Invoke-RestMethod -Uri "$scURL/rest/plugin?fields=id,xrefs&endOffset=200000" -Method Get -Headers $headers -UseBasicParsing | select -ExpandProperty "response"

# Extract all CVEs covered by plugins. 
$allCVE = @{}

#Regex expression to separate CVE IDs
$CVERegex = [regex]'CVE-\d+-\d+'

# Go over all plugins, extract CVE IDs and store them without duplicates
foreach ($xref in $result.xrefs) {
    foreach ( $match in $CVERegex.matches($xref) ) {
		if ( -not $allCVE.ContainsKey($match.value) ) {
			$allCVE.Add($match.value, '')
		}
	} 
}

#Prepare outputfile
$outputFileAllCVE = 'C:\KEV\all_CVE.txt'

#export all CVEs to file | This file contains all CVEs detected by Nessus.
$allCVE | Out-File -FilePath $outputFileAllCVE

# Get KEV from file
$kev = Import-Csv 'C:\KEV\known_exploited_vulnerabilities.csv'

# Get CVEs in KEV and not covered by Nessus
$kevNOTMatch = @()
foreach ( $cve in $kev ) {
    if ( $cve.cveID -notin $allCVE.Keys) {
        $kevNOTMatch += $cve
    }
}

#Prepare outputfile
$outputFileKEVNotCovered = 'C:\KEV\KEV_notCovered.csv'


#export to CSV KEV not covered by Nessus
$kevNOTMatch | Export-Csv -path $outputFileKEVNotCovered -NoTypeInformation 




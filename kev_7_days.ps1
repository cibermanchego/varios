$accessKey = 'ACCESS_KEY_HERE'
$secretKey = 'SECRET_KEY_HERE'
#$headers = @{'x-apikey'=@{'accesskey'=$accessKey;'secretkey'=$secretKey}}
$headers = @{}
$headers.Add("x-apikey", "accessKey=$accessKey;secretKey=$secretKey")

# Filters applied:
# 	Last observed: within the last 7 days
# 	Severity: Medium, High, Critical
$filters = @(

    @{"filterName"="lastSeen"; "operator"="="; "value"="0:7"},
    @{"filterName"="severity"; "operator"="="; "value"="2,3,4"}
)

#Query with the filters we jsut created
$query = @{"tool"="vulndetails";
            #"sourceType"="patched";
            "createdTime"=0;
            "modifiedTime"=0;
            "name"="";
            "description"="";
            "type"="vuln";
            "sortDir"="desc";
            "context"="";
            "startOffset"=0;
            "endOffset"=99999;
            "sortField"="severity";
            "filters"=$filters
}

# Body
$body = @{"sourceType"="cumulative";"type"="vuln";"query"=$query} | ConvertTo-Json -Compress -Depth 5

#Tenable.sc URL
$scURL = 'https://192.168.12.11'

# Make request to API
$result = Invoke-RestMethod -Uri $scURL/rest/analysis -Method Post -Headers $headers -Body $body -UseBasicParsing 
$queryResult = $result.response

# We get all vulnerabilities IP, CVEs, Name and pluginID
$resultFormatted = @()
foreach ($record in $queryResult.results) {
    $ip = $record.ip
    $cve = $record.cve
    $name = $record.pluginName
    $pluginID = $record.pluginID
    $resultFormatted += New-Object psobject -Property @{
        'IP' = $ip
        'CVE' = $cve
        'pluginID' = $pluginID
        'Name' = $name
    } | Select-Object IP,CVE,pluginID,Name
}

# Get contents of KEV from CISA file. 
# Download from: https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
$kev = Import-Csv 'C:\KEV\known_exploited_vulnerabilities.csv'

# Get list of CVEs matching in our DB
$kevMatch = @()
foreach ( $vuln in $resultFormatted ) {
	# Some records have multiple CVEs in a single vulnerability
    $individualCVE = $vuln.CVE -split ","
    foreach ($i in $individualCVE) {
        if ( $i -in $kev.cveID) {
            $kevMatch += $vuln
        }
    }
}

#Prepare outputfile
$outputFile = 'C:\KEV\active_kev.csv'
#export to CSV all hosts with active CVEs from the KEV list
$kevMatch | Export-Csv -path $outputFile -NoTypeInformation 

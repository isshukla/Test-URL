<#
 .Synopsis
  List the Request, Response Header Values for any site, along with Name resolution for the URL, certificate details if any.
  Same will be done for all the redirected urls (except the name resolution part). Allows users to send HTTP Headers with the request.
  
 .Description
  List the Request, Response Header Values for any site, along with Name resolution for the URL, certificate details if any.
  Same will be done for all the redirected urls (except the name resolution part). Allows users to send HTTP Headers with the request.
  
 .Parameter URL
  URL, in complete URL format
  Test-URL -URL http://Bing.com
  
 .Parameter Method
  HTTP Method, GET or HEAD
  Test-URL -url http://bing.com -Method HEAD

 .Parameter Header
  Header, allows user to pass HTTP Headers along with the request.
  Test-URL -URL http://Bing.com -Header "Test: Headercheck" 

 .Switch skipcertcheck
  skipcertcheck, to bypass certificate validation. Use it only for testing (selfsigned certificates) and known sites. Use it at your own risk.
  Test-URL -URL http://Bing.com -skipcertcheck
    
 .EXAMPLE
  Test-URL -URL http://bing.com

 .EXAMPLE
  Test-URL -URL http://bing.com:80
 
 .EXAMPLE
  Test-URL -url http://bing.com -Method HEAD
 
 .EXAMPLE 
  Test-URL -URL http://Bing.com -Header "Test: Headercheck" 
  
 .EXAMPLE  
  Test-URL -URL http://Bing.com -skipcertcheck
  


#>

#------------------------------------------------------------------------------
#
#
# THIS CODE AND ANY ASSOCIATED INFORMATION ARE PROVIDED “AS IS” WITHOUT
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
# FOR A PARTICULAR PURPOSE. THE ENTIRE RISK OF USE, INABILITY TO USE, OR
# RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
#
#------------------------------------------------------------------------------


function Test-URL () { 
Param (

    [Parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="Enter complete url: http://bing.com or http://bing.com:80")]
    [system.uri]$URL,

    [Parameter(Mandatory=$false)]
    [ValidateSet("GET", "HEAD")]
    [String]$Method,
    
    [Parameter(Mandatory=$false,
    HelpMessage="Enter Header: Test-URL -URL http://Bing.com -Header 'Test: Headercheck'")]
    [String]$Header,   

    [Parameter(Mandatory=$false,
    HelpMessage="To bypass certificate validation. Use it only for testing (selfsigned certificates) and known sites. Use it at your own risk.: 
Test-URL -URL http://Bing.com -skipcertcheck")]
    [switch]$skipcertcheck
 
)




$times = @()
$webres  = ''
$webres1 = $null
$test = $null
$test11 = $null
$redirectheaders = $null
$redirectheaders1 = $null
$errorweb = $null
$getcert = $null
$getcert1 = $null
$errorweb3 = $null
$uri = $null
$cont = $null
$cont1 = $null
$redirecturierror = $null
$weburierror = $null
$dnserrors = $null
$web = $null
$web1 = $null
$uriformaterrormessage = $null
$certerrore = $null
$certerror = $null
$certerror1 = $null
$redirecterror = $null
$certerrore1 = $null
#$Header = $null


#$url
if($url -eq ''){write-host "Enter complete url; http://bing.com or http://bing.com:80" ;Break}

if($skipcertcheck -eq $true){
Write-Warning "To bypass certificate validation. Use it only for testing (selfsigned certificates) and known sites. Use it at your own risk."
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}


$port = $url.Port
$uri = $url


# DNS Part
$TrimdURL =  $uri.Host 
Try{
$dns = Resolve-DnsName -Name $TrimdURL -ErrorAction SilentlyContinue
($dns | ft -Property Name, Namehost, Type, IPAddress, Querytype, Section  | out-string)
}

catch [System.Net.WebException],[System.Exception] {
$dnserrors = $_
}
#$dnserrors.Exception.Message




Try{
# Creating Web Request

$web = [net.webrequest]::Create($uri)
if($Method -eq 'GET'){$web.Method={GET}}
if($Method -eq 'HEAD'){$web.Method={Head}}


# Adding Header if provided.
if($Header -ne '')
{
$web.Headers.Add("$($Header)")
}


# Disable Redirect and Cache Policy
$web.AllowAutoRedirect=$false


}
Catch
{
$weburierror = $_
}
if($weburierror -ne $null){
$uriformaterrormessage = $($weburierror.Exception.InnerException.Message)
$uriformaterror = New-Object -TypeName PSObject
$uriformaterror | Add-Member -Name ErrorMessage -MemberType Noteproperty -Value $uriformaterrormessage 
$uriformaterror | Add-Member -Name OriginalString -MemberType Noteproperty -Value $($url.OriginalString;)
$uriformaterror | Add-Member -Name Example -MemberType Noteproperty -Value "Test-URL -URL https://bing.com"
($uriformaterror | FL | Out-String ).split("`n")  -match '\S'
#$web.Abort()
Break
}

try {
# Get Web response from the web request

$webres = $web.GetResponse()

# This is like Invoke-WebRequest PS Command
$test = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]::new($web.GetResponse())
$cont = $test.Content
$cont = ($cont -split '' | select -First 150) -join ''
}
catch [System.Net.WebException],[System.IO.IOException] {
    $errorweb =  $_

}

#Web error part

if($errorweb -ne $null){
 [array]$requestgeneralH = $web.Headers
 $requestgeneralV = New-Object -TypeName PSObject
 $requestgeneralV  | Add-Member -Name 'Request Headers' -MemberType NoteProperty -Value 'Request Headers'

for($i=0; $i -lt $requestgeneralH.Count; $i++){
$requestgeneralV | Add-Member -Name $requestgeneralH[$i] -MemberType Noteproperty -Value $web.Headers[$i]
}
$requestgeneralV | Add-Member -Name Method -MemberType NoteProperty -Value $web.Method
$requestgeneralV | Add-Member -Name Port -MemberType NoteProperty -Value $web.Address.Port
#"Request Headers"
($requestgeneralV | FL | Out-String ).split("`n")  -match '\S'
"`n"

#"Response-URI Headers"
$redirecterror = New-Object -TypeName PSObject
$actualerror = $($errorweb.Exception.Message) 
$redirecterror | Add-Member -Name ErrorMessage -MemberType Noteproperty -Value $actualerror


# get Cert details during web error
if($($url.Scheme) -eq 'https'){
Try{

$getcert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($web.ServicePoint.Certificate)
#$getcert | Export-Certificate -FilePath "D:\net\go.test.cer"
$redirecterror | Add-Member -Name Thumbprint -MemberType Noteproperty -Value $($getcert.Thumbprint)
$redirecterror | Add-Member -Name Subject -MemberType Noteproperty -Value $($getcert.Subject)
$redirecterror | Add-Member -Name Issuer -MemberType Noteproperty -Value $($getcert.Issuer)
$redirecterror | Add-Member -Name NotAfter -MemberType Noteproperty -Value $($getcert.NotAfter)

}
Catch {
$certerrore = $_
}
if($certerrore -ne $null){
Write-host "$($certerrore.Exception.InnerException.Message);Certificate Error"  -ForegroundColor Red}

}


If($errorweb.Exception.Response -ne $null){
$redirecterror  | Add-Member -Name ResponseHeaders -MemberType Noteproperty -Value 'Response Headers'
$errstcode = $errorweb.Exception.Response.StatusCode.value__
$errstmsg = $errorweb.Exception.Response.StatusDescription
$redirecterror | Add-Member -Name StatusCode -MemberType Noteproperty -Value $errstcode 
$redirecterror | Add-Member -Name StatusDescription -MemberType Noteproperty -Value $errstmsg

#$errorweb.Exception.Response.ResponseUri.OriginalString
[array]$rederrorresp = $errorweb.Exception.Response.Headers
$redirecterror | Add-Member -Name Original-URI -MemberType NoteProperty -Value $($errorweb.Exception.Response.ResponseUri.OriginalString)
for($i=0; $i -lt $rederrorresp.Count; $i++){
$redirecterror | Add-Member -Name $rederrorresp[$i] -MemberType NoteProperty -Value $($errorweb.Exception.Response.Headers[$i])
}

}

if($errorweb.Exception.Response -eq $null){
$redirecterror | Add-Member -Name Original-URI -MemberType NoteProperty -Value $url.OriginalString
}

($redirecterror | FL | Out-String ).split("`n")  -match '\S'
$web.Abort()
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
break
}

 [array]$requestgeneralH = $web.Headers
 $requestgeneralV = New-Object -TypeName PSObject
 $requestgeneralV | Add-Member -Name 'Request Headers' -MemberType NoteProperty -Value 'Request Headers'

for($i=0; $i -lt $requestgeneralH.Count; $i++){
$requestgeneralV | Add-Member -Name $requestgeneralH[$i] -MemberType Noteproperty -Value $web.Headers[$i]
}

$requestgeneralV | Add-Member -Name Method -MemberType NoteProperty -Value $web.Method
$requestgeneralV | Add-Member -Name Port -MemberType NoteProperty -Value $web.Address.Port
($requestgeneralV | FL | out-string).split("`n")  -match '\S'
"`n"

# Certificate Part

if($($url.Scheme) -eq 'https'){
Try{

$getcert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($web.ServicePoint.Certificate)
#$getcert | Export-Certificate -FilePath "D:\net\go.test.cer"

}
Catch {
$certerror = $_
}
if($certerror -ne $null){
Write-host "$($certerror.Exception.InnerException.Message);Certificate Error"  -ForegroundColor Red}

}

# Creating a variable to hold the current header value names avaialble for the Web Response
[array]$rehead = $webres.Headers

# Creating a Custom object to hold the Header names and values
$redirectheaders = New-Object -TypeName PSObject

# Updating the Request URI, Http status code and Description
#$redirectheaders | Add-Member -Name General -MemberType NoteProperty -Value 'General Info'
$redirectheaders | Add-Member -Name Request-URI -MemberType Noteproperty -Value $uri
$redirectheaders | Add-Member -Name ResponseHeaders -MemberType Noteproperty -Value 'Response Headers' 
$redirectheaders | Add-Member -Name StatusCode -MemberType Noteproperty -Value $($test.StatusCode)
$redirectheaders | Add-Member -Name StatusDescription -MemberType Noteproperty -Value $($test.StatusDescription)
$redirectheaders | Add-Member -Name Content -MemberType Noteproperty -Value $cont
if($( $url.Scheme) -eq 'https'){
$redirectheaders | Add-Member -Name Thumbprint -MemberType Noteproperty -Value $($getcert.Thumbprint)
$redirectheaders | Add-Member -Name Subject -MemberType Noteproperty -Value $($getcert.Subject)
$redirectheaders | Add-Member -Name Issuer -MemberType Noteproperty -Value $($getcert.Issuer)
$redirectheaders | Add-Member -Name NotAfter -MemberType Noteproperty -Value $($getcert.NotAfter)
}

# For loop to get the request header values from the Web Response and put them in the variable as diff objects
for($i=0; $i -lt $rehead.Count; $i++){
$redirectheaders | Add-Member -Name $rehead[$i] -MemberType Noteproperty -Value $webres.Headers[$i]
}


($redirectheaders | FL | out-string).split("`n")  -match '\S'
"`n"
"`n"
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
# Closing the Web Request
$web.Abort()
 


if ($($redirectheaders.location) -ne $null){

##############
##############


## Part 2 ################

Do{
$webres1 = ''
$times += $uri1




if($times.count -eq '1'){
$uri1 = $redirectheaders.location}
Else{$uri1 = $redirectheaders1.Location}

try{
$web1 = [net.webrequest]::Create($uri1)
$web1.AllowAutoRedirect=$false
$cachepol = [System.Net.Cache.RequestCacheLevel]::NoCacheNoStore
$web1.CachePolicy=$cachepol
}
Catch {
$redirecturierror = $_
}

if($redirecturierror -ne $null){
$redurilocerrmsg = "$($redirecturierror.Exception.InnerException.Message) This Module cannot redirect to location which are not in URL Format, yet."
$redirecturierrorobj1 = New-Object -TypeName PSObject
$redirecturierrorobj1 | Add-Member -Name Redirect-location -MemberType NoteProperty -Value $uri1
$redirecturierrorobj1 | Add-Member -Name Redirect-locationError -MemberType NoteProperty -Value $redurilocerrmsg
($redirecturierrorobj1 | FL | Out-String ).split("`n")  -match '\S'
$web.Abort()
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
Break
}


try {
if($skipcertcheck -eq $true){
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}
$webres1 = $web1.GetResponse() 
$test11 = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]::new($web1.GetResponse())
$cont1 = $test11.Content
$cont1 = ($cont1 -split '' | select -First 150) -join ''

}
catch [System.Net.WebException],[System.IO.IOException] {
     $errorweb3 =  $_ 
}

if($errorweb3 -ne $null){
 [array]$requestgeneralH2 = $web1.Headers
$requestgeneralV2 = New-Object -TypeName PSObject
$requestgeneralV2 | Add-Member -Name Redirect-Request -MemberType NoteProperty -Value 'Redirect Request'
$requestgeneralV2 | Add-Member -Name Method -MemberType NoteProperty -Value $web1.Method
$requestgeneralV2 | Add-Member -Name Port -MemberType NoteProperty -Value $web1.Address.Port

for($i=0; $i -lt $requestgeneralH2.Count; $i++){
$requestgeneralV2 | Add-Member -Name $requestgeneralH2[$i] -MemberType Noteproperty -Value $web1.Headers[$i]
}
#Write-Host "Redirect Headers" -NoNewline -ForegroundColor Green
$requestgeneralV2 | FL
$web.Abort()
$web1.abort()
if($($url.Scheme) -eq 'https') {
$tcp.Close()
}

#"Redirect-URI Response"
$redirecterror1 = New-Object -TypeName PSObject

$actualerror1 = $($errorweb3.Exception.Message) 
$redirecterror1 | Add-Member -Name ErrorMessage -MemberType Noteproperty -Value $actualerror1



if($($web1.Address.Scheme) -eq 'https'){
Try{

$getcert1 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($web1.ServicePoint.Certificate)
$redirecterror1 | Add-Member -Name Thumbprint -MemberType Noteproperty -Value $($getcert1.Thumbprint)
$redirecterror1 | Add-Member -Name Subject -MemberType Noteproperty -Value $($getcert1.Subject)
$redirecterror1 | Add-Member -Name Issuer -MemberType Noteproperty -Value $($getcert1.Issuer)
$redirecterror1 | Add-Member -Name NotAfter -MemberType Noteproperty -Value $($getcert1.NotAfter)
#$getcert | Export-Certificate -FilePath "D:\net\$uri.cer"
}
Catch {
$certerrore1 = $_
}
if($certerrore1 -ne $null){
Write-host "$($certerrore1.Exception.InnerException.Message);Certificate Error"  -ForegroundColor Red}

}


If($errorweb3.Exception.Response -ne $null){
$redirecterror1  | Add-Member -Name Redirect-Response -MemberType Noteproperty -Value 'Redirect Response'
$errstcode1 = $errorweb3.Exception.Response.StatusCode.value__
$errstmsg1 = $errorweb3.Exception.Response.StatusDescription
$redirecterror1 | Add-Member -Name StatusCode -MemberType Noteproperty -Value $errstcode1 
$redirecterror1 | Add-Member -Name StatusDescription -MemberType Noteproperty -Value $errstmsg1

[array]$rederrorresp1 = $errorweb3.Exception.Response.Headers

$redirecterror1 | Add-Member -Name Redirect-URI -MemberType NoteProperty -Value $($errorweb3.Exception.Response.ResponseUri.OriginalString)

for($i=0; $i -lt $rederrorresp1.Count; $i++){
$redirecterror1 | Add-Member -Name $rederrorresp1[$i] -MemberType NoteProperty -Value $($errorweb3.Exception.Response.Headers[$i])
}


}

If($errorweb3.Exception.Response -eq $null){
$redirecterror1 | Add-Member -Name Redirect-URI -MemberType NoteProperty -Value $uri1

}

($redirecterror1 | FL | Out-String ).split("`n")  -match '\S'
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
break
}

 [array]$requestgeneralH2 = $web1.Headers
 $requestgeneralV2 = New-Object -TypeName PSObject
 $requestgeneralV2 | Add-Member -Name Redirect-Requests -MemberType NoteProperty -Value 'Redirect Request'
 $requestgeneralV2 | Add-Member -Name Method -MemberType NoteProperty -Value $web1.Method
 $requestgeneralV2 | Add-Member -Name Port -MemberType NoteProperty -Value $web1.Address.Port

for($i=0; $i -lt $requestgeneralH2.Count; $i++){
$requestgeneralV2 | Add-Member -Name $requestgeneralH2[$i] -MemberType Noteproperty -Value $web1.Headers[$i]
}


($requestgeneralV2 | FL | out-string).split("`n")  -match '\S'
"`n"

# Certificate Part

if($($web1.Address.Scheme) -eq 'https'){
Try{

$getcert1 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($web1.ServicePoint.Certificate)

#$getcert | Export-Certificate -FilePath "D:\net\$uri.cer"
}
Catch {
$certerror1 = $_
}
if($certerror1 -ne $null){
Write-host "$($certerror1.Exception.InnerException.Message);Certificate Error"  -ForegroundColor Red}

}



[array]$rehead1 = $webres1.Headers
$redirectheaders1 = New-Object -TypeName PSObject
#$redirectheaders1 | Add-Member -Name General -MemberType NoteProperty -Value 'General Info'
$redirectheaders1 | Add-Member -Name Redirect-URI -MemberType Noteproperty -Value $uri1 
$redirectheaders1 | Add-Member -Name Redirect-Response -MemberType NoteProperty -Value 'Redirect Response'
$redirectheaders1 | Add-Member -Name StatusCode -MemberType Noteproperty -Value $($test11.StatusCode) 
$redirectheaders1 | Add-Member -Name StatusDescription -MemberType Noteproperty -Value $($test11.StatusDescription) 
$redirectheaders1 | Add-Member -Name Content -MemberType Noteproperty -Value $cont1
if($($web1.Address.Scheme) -eq 'https'){
$redirectheaders1 | Add-Member -Name Thumbprint -MemberType Noteproperty -Value $($getcert1.Thumbprint)
$redirectheaders1 | Add-Member -Name Subject -MemberType Noteproperty -Value $($getcert1.Subject)
$redirectheaders1 | Add-Member -Name Issuer -MemberType Noteproperty -Value $($getcert1.Issuer)
$redirectheaders1 | Add-Member -Name NotAfter -MemberType Noteproperty -Value $($getcert1.NotAfter)
}


for($i=0; $i -lt $rehead1.Count; $i++){
$redirectheaders1 | Add-Member -Name $rehead1[$i] -MemberType Noteproperty -Value $webres1.Headers[$i] 
}


#Write-Host "Response Headers" -NoNewline -ForegroundColor Green
($redirectheaders1 | FL| out-string).split("`n")  -match '\S'
"`n"


# Check to limit the number of Redirections
if($times.Count -gt '20')
{
"Maximum redirection limit for this module reached"
$web.Abort()
$web1.abort()
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
Break
}

}

While ($redirectheaders1.location -ne $null   )
if($web1 -ne $null)
{$web1.abort()}

}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null

}


Export-ModuleMember -Function Test-URL


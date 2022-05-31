
$opensslLocation = "C:\Program Files\Git\usr\bin\openssl.exe"

Set-Alias -Name openssl -Value $opensslLocation

$cn = "digisign.poc.org"

# Generate SS-Cert
openssl req -newkey rsa:2048 -subj "/CN=$cn" -nodes -keyout "$cn.key" -x509 -days 365 -out "$cn.crt"

# Export as PFX
openssl pkcs12 -export -inkey "$cn.key" -in "$cn.crt" -out "$cn.pfx" -passout "pass:HelloWorld"


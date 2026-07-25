# Win-StandardUser-Checks.ps1
# Standard-user Windows posture checks for authorized MDM/CA assessment (redblacksoftware.com)
# No admin required. Non-destructive. Copy-paste the whole thing into a normal PowerShell window.

$results = New-Object System.Collections.Generic.List[object]
function Add-Result($Check,$Status,$Severity,$Detail){
  $results.Add([pscustomobject]@{Check=$Check;Status=$Status;Severity=$Severity;Detail=$Detail})
}
function Get-Line($arr,$pat){ $m=$arr|Select-String $pat|Select-Object -First 1; if($m){ ($m.Line -split ':',2)[-1].Trim() } else { $null } }

Write-Host "`n==== Windows Standard-User Checks (redblacksoftware) ====`n" -ForegroundColor Cyan

# ---- Context ----
try {
  $me=whoami
  $isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  Add-Result "Context user" "INFO" "-" "$me  LocalAdmin=$isAdmin"
} catch {}
try {
  $ds=dsregcmd /status 2>$null
  Add-Result "Device join" "INFO" "-" ("AzureAdJoined=" + (Get-Line $ds 'AzureAdJoined') + "  MDM=" + (Get-Line $ds 'MDMUrl'))
} catch {}

# ---- CHECK 1: Device Lock / password policy ----
try {
  $na=net accounts 2>$null
  $minlen=Get-Line $na 'Minimum password length'
  $maxage=Get-Line $na 'Maximum password age'
  $lockout=Get-Line $na 'Lockout threshold'
  $dl=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" -EA SilentlyContinue
  $applied=[bool]$dl
  $cspLen=$dl.MinDevicePasswordLength
  $eff=0; if($cspLen){$eff=[int]$cspLen}elseif($minlen -match '^\d+$'){$eff=[int]$minlen}
  if(-not $applied -and $eff -le 0){
    Add-Result "Device Lock policy" "FAIL" "HIGH" "No DeviceLock CSP applied; net-accounts min length='$minlen' -> endpoint may enforce NO lock/PIN (Assignment-failure finding)"
  } elseif($eff -lt 8){
    Add-Result "Device Lock policy" "FAIL" "MEDIUM" "Min password length=$eff (weak). CSP applied=$applied lockout='$lockout' maxage='$maxage'"
  } else {
    Add-Result "Device Lock policy" "PASS" "-" "Min length=$eff CSP=$applied lockout='$lockout'"
  }
} catch { Add-Result "Device Lock policy" "ERROR" "-" $_.Exception.Message }

# ---- CHECK 2: BitLocker (OS drive) ----
try {
  $bl=Get-BitLockerVolume -MountPoint $env:SystemDrive -EA SilentlyContinue
  if($bl){
    if($bl.ProtectionStatus -eq 'On'){ Add-Result "BitLocker OS drive" "PASS" "-" "$($bl.VolumeStatus) $($bl.EncryptionPercentage)% ProtectionOn" }
    else { Add-Result "BitLocker OS drive" "FAIL" "HIGH" "Not protected: $($bl.VolumeStatus) ProtectionStatus=$($bl.ProtectionStatus)" }
  } else {
    $mb=(manage-bde -status $env:SystemDrive 2>$null|Select-String "Protection Status")
    if($mb){ Add-Result "BitLocker OS drive" "INFO" "-" ($mb.Line.Trim()) }
    else   { Add-Result "BitLocker OS drive" "INFO" "-" "Not readable as standard user" }
  }
} catch { Add-Result "BitLocker OS drive" "INFO" "-" "Access denied (needs admin)" }

# ---- CHECK 3: Firewall + Defender/EDR ----
try {
  $fw=Get-NetFirewallProfile -EA SilentlyContinue
  $off=$fw|Where-Object{$_.Enabled -ne $true}
  if($off){ Add-Result "Windows Firewall" "FAIL" "MEDIUM" ("Disabled: "+($off.Name -join ',')) }
  else    { Add-Result "Windows Firewall" "PASS" "-" "All profiles enabled" }
} catch {}
try {
  $mp=Get-MpComputerStatus -EA SilentlyContinue
  if($mp){ Add-Result "Defender AV" "INFO" "-" "Mode=$($mp.AMRunningMode) RTP=$($mp.RealTimeProtectionEnabled) (passive => CrowdStrike primary)" }
} catch {}
try {
  $cs=Get-Service -EA SilentlyContinue|Where-Object{$_.DisplayName -match "CrowdStrike|Falcon"}
  if($cs){ Add-Result "CrowdStrike sensor" "PASS" "-" ("Present: "+($cs.Status -join ',')) }
  else   { Add-Result "CrowdStrike sensor" "FAIL" "HIGH" "CrowdStrike service NOT found -> EDR compliance gate absent on this host" }
} catch {}

# ---- CHECK 4: IME logs / secrets ----
try {
  $ime="$env:ProgramData\Microsoft\IntuneManagementExtension"
  if(Test-Path "$ime\Logs"){
    $hits=Select-String -Path "$ime\Logs\*.log" -Pattern "password=|clientsecret|-Credential|ConvertTo-SecureString|BEGIN PRIVATE KEY|AccessToken" -EA SilentlyContinue
    if($hits){ Add-Result "IME log secrets" "FAIL" "MEDIUM" ("Possible secrets in IME logs: "+$hits.Count+" hits (review manually)") }
    else     { Add-Result "IME log secrets" "PASS" "-" "IME logs readable, no obvious secrets" }
    $sc=Get-ChildItem "$ime\Policies\Scripts","$ime\SideCarPolicies\Scripts\Download" -Recurse -EA SilentlyContinue
    if($sc){ Add-Result "IME cached scripts" "INFO" "LOW" ($sc.Count.ToString()+" script(s) readable (incl. compliance scripts)") }
  } else { Add-Result "IME logs" "INFO" "-" "Not present/readable" }
} catch {}

# ---- CHECK 5: Cato (enumerate only - tamper is manual/disruptive) ----
try {
  $cato=Get-Service -EA SilentlyContinue|Where-Object{$_.DisplayName -match "Cato"}
  if($cato){
    Add-Result "Cato client" "INFO" "-" ("Svc="+($cato.Name -join ',')+" Status="+($cato.Status -join ',')+" Start="+($cato.StartType -join ','))
    try { $sd=& sc.exe sdshow $cato[0].Name 2>$null; Add-Result "Cato service ACL" "INFO" "-" ("$sd  (AU with WP/WD => non-admin can stop = FINDING)") } catch {}
    Add-Result "Cato tamper (MANUAL)" "INFO" "-" ("Run deliberately: Stop-Service "+$cato[0].Name+"  -> success = non-admin can drop tunnel (disruptive)")
  } else { Add-Result "Cato client" "INFO" "-" "No Cato service found" }
  $ip=try{(Invoke-RestMethod "https://ifconfig.me/ip" -TimeoutSec 8).Trim()}catch{"n/a"}
  Add-Result "Egress public IP" "INFO" "-" "$ip  (compare to F2 trusted location / office / Cato PoP)"
} catch {}

# ---- CHECK 6: Credential-theft prerequisites (recon for PRT-key path) ----
try {
  $ppl=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -EA SilentlyContinue).RunAsPPL
  Add-Result "LSASS RunAsPPL" ($(if($ppl -eq 1){"PASS"}else{"INFO"})) "-" "RunAsPPL=$ppl (1=protected)"
  $dg=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA SilentlyContinue
  $cg=($dg.SecurityServicesRunning -contains 1)
  Add-Result "Credential Guard" ($(if($cg){"PASS"}else{"INFO"})) "-" "Running=$cg (ON => PRT session-key theft blocked even with admin)"
} catch {}

# ---- CHECK 7: local admins / UAC / execution ----
try { Add-Result "Local Administrators" "INFO" "-" ((Get-LocalGroupMember Administrators -EA SilentlyContinue).Name -join '; ') } catch {}
try {
  $lua=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -EA SilentlyContinue).EnableLUA
  Add-Result "UAC EnableLUA" ($(if($lua -eq 1){"PASS"}else{"FAIL"})) ($(if($lua -eq 1){"-"}else{"HIGH"})) "EnableLUA=$lua"
} catch {}
try { Add-Result "PS ExecutionPolicy" "INFO" "-" ((Get-ExecutionPolicy -List|ForEach-Object{"$($_.Scope)=$($_.ExecutionPolicy)"}) -join ' ') } catch {}

# ================= SUMMARY =================
Write-Host "`n================ RESULTS ================`n" -ForegroundColor Cyan
foreach($r in $results){
  $c=switch($r.Status){"FAIL"{"Red"}"PASS"{"Green"}"ERROR"{"DarkYellow"}default{"Yellow"}}
  Write-Host ("[{0,-5}] {1,-24} {2}" -f $r.Status,$r.Check,$r.Detail) -ForegroundColor $c
}
$f=$results|Where-Object{$_.Status -eq "FAIL"}
$p=($results|Where-Object{$_.Status -eq "PASS"}).Count
Write-Host ("`nPASS={0}  FAIL={1}  (INFO/context={2})" -f $p,($f|Measure-Object).Count,($results.Count-$p-($f|Measure-Object).Count)) -ForegroundColor Cyan
Write-Host "`n---- REAL FINDINGS (FAIL) ----" -ForegroundColor Red
if($f){ $f|ForEach-Object{ Write-Host ("  [{0}] {1} -> {2}" -f $_.Severity,$_.Check,$_.Detail) -ForegroundColor Red } }
else  { Write-Host "  none - all tested controls held" -ForegroundColor Green }
Write-Host "`n(Copy this whole output back for logging.)`n" -ForegroundColor Cyan

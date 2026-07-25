# Win-StandardUser-Checks.ps1  (v3)
# Standard-user Windows posture checks + sensitive-data hunt for authorized MDM/CA assessment.
# No admin required. Non-destructive. Writes report + CSV + sensitive-hits files.
# Copy-paste the whole thing into a normal PowerShell window, or run the .ps1.

# ---------- output setup ----------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$out   = Join-Path $env:USERPROFILE "Desktop\WinChecks_$stamp"
New-Item -ItemType Directory -Path $out -Force | Out-Null
$reportTxt = Join-Path $out 'report.txt'
$resultCsv = Join-Path $out 'results.csv'
$sensTxt   = Join-Path $out 'sensitive_hits.txt'
$sensCsv   = Join-Path $out 'sensitive_hits.csv'

$results = New-Object System.Collections.Generic.List[object]
function Add-Result($Check,$Status,$Severity,$Detail){ $results.Add([pscustomobject]@{Check=$Check;Status=$Status;Severity=$Severity;Detail=$Detail}) }
function Get-Line($arr,$pat){ $m=$arr|Select-String $pat|Select-Object -First 1; if($m){ ($m.Line -split ':',2)[-1].Trim() } else { $null } }

Write-Host "`n==== Windows Standard-User Checks (v3) ====  output: $out`n" -ForegroundColor Cyan

# ---------- POSTURE CHECKS ----------
try { $me=whoami; $isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); Add-Result "Context user" "INFO" "-" "$me LocalAdmin=$isAdmin" } catch {}
try { $ds=dsregcmd /status 2>$null; Add-Result "Device join" "INFO" "-" ("AzureAdJoined="+(Get-Line $ds 'AzureAdJoined')+" MDM="+(Get-Line $ds 'MDMUrl')+" NgcSet="+(Get-Line $ds 'NgcSet')) } catch {}
try {
  $na=net accounts 2>$null; $minlen=Get-Line $na 'Minimum password length'; $lockout=Get-Line $na 'Lockout threshold'
  $dl=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock" -EA SilentlyContinue; $applied=[bool]$dl; $cspLen=$dl.MinDevicePasswordLength
  $eff=0; if($cspLen){$eff=[int]$cspLen}elseif($minlen -match '^\d+$'){$eff=[int]$minlen}
  if(-not $applied -and $eff -le 0){ Add-Result "Device Lock policy" "FAIL" "HIGH" "No DeviceLock CSP; net-accounts min length='$minlen' -> possibly NO lock/PIN enforced" }
  elseif($eff -lt 8){ Add-Result "Device Lock policy" "FAIL" "MEDIUM" "Min length=$eff (weak) CSP=$applied lockout='$lockout'" }
  else { Add-Result "Device Lock policy" "PASS" "-" "Min length=$eff CSP=$applied lockout='$lockout'" }
} catch { Add-Result "Device Lock policy" "ERROR" "-" $_.Exception.Message }
try { $bl=Get-BitLockerVolume -MountPoint $env:SystemDrive -EA SilentlyContinue; if($bl){ if($bl.ProtectionStatus -eq 'On'){ Add-Result "BitLocker OS drive" "PASS" "-" "$($bl.VolumeStatus) $($bl.EncryptionPercentage)%" } else { Add-Result "BitLocker OS drive" "FAIL" "HIGH" "Not protected: $($bl.VolumeStatus)" } } else { Add-Result "BitLocker OS drive" "INFO" "-" "Not readable as standard user" } } catch { Add-Result "BitLocker OS drive" "INFO" "-" "Access denied" }
try { $fw=Get-NetFirewallProfile -EA SilentlyContinue; $offp=$fw|Where-Object{$_.Enabled -ne $true}; if($offp){ Add-Result "Windows Firewall" "FAIL" "MEDIUM" ("Disabled: "+($offp.Name -join ',')) } else { Add-Result "Windows Firewall" "PASS" "-" "All profiles enabled" } } catch {}
try { $mp=Get-MpComputerStatus -EA SilentlyContinue; if($mp){ Add-Result "Defender AV" "INFO" "-" "Mode=$($mp.AMRunningMode) RTP=$($mp.RealTimeProtectionEnabled) Tamper=$($mp.IsTamperProtected)" } } catch {}
try { $cs=Get-Service -EA SilentlyContinue|Where-Object{$_.DisplayName -match "CrowdStrike|Falcon"}; if($cs){ Add-Result "CrowdStrike sensor" "PASS" "-" ("Present: "+($cs.Status -join ',')) } else { Add-Result "CrowdStrike sensor" "FAIL" "HIGH" "CrowdStrike NOT found on this host" } } catch {}
try { $wd=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name UseLogonCredential -EA SilentlyContinue).UseLogonCredential; if($wd -eq 1){ Add-Result "WDigest plaintext" "FAIL" "HIGH" "UseLogonCredential=1 -> plaintext creds in LSASS" } else { Add-Result "WDigest plaintext" "PASS" "-" "UseLogonCredential=$wd" } } catch {}
try { $alg=Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA SilentlyContinue; if($alg.DefaultPassword){ Add-Result "Autologon password" "FAIL" "HIGH" "DefaultPassword stored (plaintext)" } elseif($alg.AutoAdminLogon -eq 1){ Add-Result "Autologon" "FAIL" "MEDIUM" "AutoAdminLogon=1" } else { Add-Result "Autologon" "PASS" "-" "Not configured" }; Add-Result "Cached logons" "INFO" "-" ("CachedLogonsCount="+$alg.CachedLogonsCount) } catch {}
try { $os=Get-CimInstance Win32_OperatingSystem; $bld=[int]$os.BuildNumber; Add-Result "OS build" ($(if($bld -ge 22631){"PASS"}else{"FAIL"})) ($(if($bld -ge 22631){"-"}else{"MEDIUM"})) "$($os.Caption) build $bld"; $hf=Get-HotFix -EA SilentlyContinue|Sort-Object InstalledOn -Desc|Select-Object -First 1; $stale=$hf -and $hf.InstalledOn -lt (Get-Date).AddDays(-45); Add-Result "Patch currency" ($(if($stale){"FAIL"}else{"INFO"})) ($(if($stale){"MEDIUM"}else{"-"})) ("last: "+$hf.HotFixID+" "+$hf.InstalledOn) } catch {}
try { $ppl=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL -EA SilentlyContinue).RunAsPPL; Add-Result "LSASS RunAsPPL" ($(if($ppl -eq 1){"PASS"}else{"INFO"})) "-" "RunAsPPL=$ppl"; $dg=Get-CimInstance Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -EA SilentlyContinue; $cg=($dg.SecurityServicesRunning -contains 1); Add-Result "Credential Guard" ($(if($cg){"PASS"}else{"INFO"})) "-" "Running=$cg" ; Add-Result "WDAC CodeIntegrity" "INFO" "-" ("Enforcement="+$dg.CodeIntegrityPolicyEnforcementStatus+" (2=enforced)") } catch {}
try { Add-Result "PS LanguageMode" ($(if($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage'){"INFO"}else{"PASS"})) "-" "$($ExecutionContext.SessionState.LanguageMode)"; $sbl=(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -EA SilentlyContinue).EnableScriptBlockLogging; Add-Result "PS ScriptBlock logging" ($(if($sbl -eq 1){"PASS"}else{"INFO"})) "-" "Enabled=$sbl" } catch {}
try { $ap=Get-AppLockerPolicy -Effective -EA SilentlyContinue; $rc=($ap.RuleCollections|ForEach-Object{$_.Count}|Measure-Object -Sum).Sum; Add-Result "AppLocker" ($(if($rc){"PASS"}else{"INFO"})) "-" "Effective rules=$rc" } catch { Add-Result "AppLocker" "INFO" "-" "not configured" }
try { $rdp=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections; $nla=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -EA SilentlyContinue).UserAuthentication; if($rdp -eq 0 -and $nla -ne 1){ Add-Result "RDP" "FAIL" "MEDIUM" "Enabled without NLA" } elseif($rdp -eq 0){ Add-Result "RDP" "INFO" "-" "Enabled, NLA on" } else { Add-Result "RDP" "PASS" "-" "Disabled" } } catch {}
try { $ba=Get-LocalUser -EA SilentlyContinue|Where-Object{$_.SID -like "*-500"}; if($ba){ Add-Result "Built-in Admin acct" ($(if($ba.Enabled){"FAIL"}else{"PASS"})) ($(if($ba.Enabled){"MEDIUM"}else{"-"})) "Enabled=$($ba.Enabled)" } } catch {}
try { $lua=(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -EA SilentlyContinue).EnableLUA; Add-Result "UAC EnableLUA" ($(if($lua -eq 1){"PASS"}else{"FAIL"})) ($(if($lua -eq 1){"-"}else{"HIGH"})) "EnableLUA=$lua" } catch {}
try { Add-Result "Local Administrators" "INFO" "-" ((Get-LocalGroupMember Administrators -EA SilentlyContinue).Name -join '; ') } catch {}
try { $cato=Get-Service -EA SilentlyContinue|Where-Object{$_.DisplayName -match "Cato"}; if($cato){ Add-Result "Cato client" "INFO" "-" ("Svc="+($cato.Name -join ',')+" Status="+($cato.Status -join ',')) } else { Add-Result "Cato client" "INFO" "-" "None found" }; $ip=try{(Invoke-RestMethod "https://ifconfig.me/ip" -TimeoutSec 8).Trim()}catch{"n/a"}; Add-Result "Egress public IP" "INFO" "-" "$ip (compare to F2 trusted location)" } catch {}

try { $asr=(Get-MpPreference -EA SilentlyContinue).AttackSurfaceReductionRules_Ids; Add-Result "Defender ASR rules" "INFO" "-" (($asr.Count).ToString()+" rule(s) set (N/A if Defender passive)") } catch {}
try { $sss=(Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -EA SilentlyContinue).ScreenSaverIsSecure; $sst=(Get-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut -EA SilentlyContinue).ScreenSaveTimeOut; Add-Result "Screen lock" ($(if($sss -eq 1){"PASS"}else{"INFO"})) "-" "SecureScreensaver=$sss Timeout=${sst}s" } catch {}

# ---------- SENSITIVE-DATA HUNT (logs + scripts) ----------
Write-Host "Scanning logs + scripts for sensitive data..." -ForegroundColor Cyan
$patterns = @(
  'password\s*[=:]','passwd','pwd\s*=','client_?secret','api[_-]?key','secret\s*[=:]',
  'access_?token','refresh_?token','bearer\s+[A-Za-z0-9\-_\.]{10,}','authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}',
  'BEGIN (RSA|OPENSSH|EC|DSA|ENCRYPTED)? ?PRIVATE KEY','AKIA[0-9A-Z]{16}','aws_secret_access_key',
  'connectionstring','Data Source=.*Password=','ConvertTo-SecureString','-AsPlainText',
  'xox[baprs]-[A-Za-z0-9-]+','ghp_[A-Za-z0-9]{36}','eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}'
)
$rx = ($patterns -join '|')
$scanPaths = @(
  "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs",
  "$env:ProgramData\Microsoft\IntuneManagementExtension\Policies\Scripts",
  "$env:ProgramData\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Download",
  "$env:ProgramData\Microsoft\IntuneManagementExtension\Content",
  "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine",
  "$env:TEMP","C:\Windows\Panther","C:\Windows\System32\Sysprep","C:\Users\Public","C:\ProgramData\Cato Networks"
)
$hits = New-Object System.Collections.Generic.List[object]
foreach($base in $scanPaths){
  if(-not (Test-Path $base)){ continue }
  Get-ChildItem $base -Recurse -File -Include *.log,*.txt,*.ps1,*.psm1,*.xml,*.json,*.config,*.cfg,*.ini,*.bat,*.cmd,*.csv,*.history -EA SilentlyContinue | ForEach-Object {
    $fp=$_.FullName
    try {
      Select-String -Path $fp -Pattern $rx -AllMatches -EA SilentlyContinue | ForEach-Object {
        $line=$_.Line.Trim(); if($line.Length -gt 200){$line=$line.Substring(0,200)}
        $hits.Add([pscustomobject]@{ File=$fp; Line=$_.LineNumber; Match=$_.Matches[0].Value; Snippet=$line })
      }
    } catch {}
  }
}
# provisioning packages (bulk enroll tokens)
$ppkg = Get-ChildItem "C:\Recovery","$env:USERPROFILE\Downloads","C:\ProgramData" -Include *.ppkg -Recurse -File -EA SilentlyContinue
if($ppkg){ foreach($p in $ppkg){ $hits.Add([pscustomobject]@{File=$p.FullName;Line=0;Match='.ppkg (bulk enroll token)';Snippet='Provisioning package present'}) } }

if($hits.Count){ Add-Result "Sensitive data in logs/scripts" "FAIL" "HIGH" ("$($hits.Count) potential secret(s) found -> see sensitive_hits.txt") }
else { Add-Result "Sensitive data in logs/scripts" "PASS" "-" "No secrets matched in scanned logs/scripts" }

# ---------- WRITE FILES ----------
$results | Export-Csv -Path $resultCsv -NoTypeInformation -Encoding UTF8
$hits | Export-Csv -Path $sensCsv -NoTypeInformation -Encoding UTF8
$rep = @()
$rep += "Windows Standard-User Checks - $stamp"
$rep += "Host: $env:COMPUTERNAME  User: $env:USERNAME"
$rep += ("="*60)
foreach($r in $results){ $rep += ("[{0,-5}] {1,-26} {2}" -f $r.Status,$r.Check,$r.Detail) }
$rep += ""; $rep += "REAL FINDINGS (FAIL):"
($results|Where-Object{$_.Status -eq 'FAIL'}) | ForEach-Object { $rep += ("  [{0}] {1} -> {2}" -f $_.Severity,$_.Check,$_.Detail) }
$rep | Out-File -FilePath $reportTxt -Encoding UTF8
$sen = @("Sensitive-data hits - $stamp","="*60)
foreach($h in $hits){ $sen += ("{0}:{1}  [{2}]`n    {3}" -f $h.File,$h.Line,$h.Match,$h.Snippet) }
$sen | Out-File -FilePath $sensTxt -Encoding UTF8

# ---------- CONSOLE SUMMARY ----------
Write-Host "`n================ RESULTS ================`n" -ForegroundColor Cyan
foreach($r in $results){ $c=switch($r.Status){"FAIL"{"Red"}"PASS"{"Green"}"ERROR"{"DarkYellow"}default{"Yellow"}}; Write-Host ("[{0,-5}] {1,-26} {2}" -f $r.Status,$r.Check,$r.Detail) -ForegroundColor $c }
Write-Host "`n---- REAL FINDINGS (FAIL) ----" -ForegroundColor Red
$f=$results|Where-Object{$_.Status -eq "FAIL"}
if($f){ $f|ForEach-Object{ Write-Host ("  [{0}] {1} -> {2}" -f $_.Severity,$_.Check,$_.Detail) -ForegroundColor Red } } else { Write-Host "  none - all tested controls held" -ForegroundColor Green }
Write-Host ("`nSensitive hits: {0}   Files written to: {1}" -f $hits.Count,$out) -ForegroundColor Cyan
Write-Host "  report.txt | results.csv | sensitive_hits.txt | sensitive_hits.csv`n" -ForegroundColor Cyan

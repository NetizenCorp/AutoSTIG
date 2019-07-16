#######################################
#####START SCRIPT SCOPE VARIABLES######
#######################################

$script:stigText=$null #array that holds seed ckl file in memory
$script:XCCDF=$null #array that holds seed XCCDF file in memory
$script:isClassified=$null #overall system classification
$script:isStandAlone=$null #Holds Boolean Determination if Host is Stand Alone
$script:computerName=$null #Holds computer name
$script:OSReleaseID=$null #Holds OS Release ID
$script:isVirtualMachine=$null #Holds Boolean Determination if OS is Virtual
$script:installedSoftware=$null #Holds installed software on server

######################################
#####END SCRIPT SCOPE VARIABLES#######
######################################

################################
#####START HELPER FUNCTIONS#####
################################

function updateVulnStatus([string]$vulID,[string]$status){
 $Vulns=$stigText.CHECKLIST.STIGS.iSTIG.VULN 
  foreach($vuln in $Vulns){
   if($vuln.STIG_DATA.ATTRIBUTE_DATA -eq $vulID){
    $Vuln.STATUS=$status 
   }
  }
}

function updateStigCommentsField([string]$vulID,[string]$commentText){
 $comments=$stigText.CHECKLIST.STIGS.iSTIG.VULN  
  foreach($comment in $comments){
   if($comment.STIG_DATA.ATTRIBUTE_DATA -eq $vulID){
    $comment.FINDING_DETAILS=$commentText  
   }
  }
}

function loadXCCDF{
$script:XCCDF=(Get-Content -Path .\Seed_XCCDF\*.xml -ErrorAction SilentlyContinue) 
if(([xml]$script:XCCDF | Measure-Object).Count -eq 0){
   Write-Output "*****No XCCDF File Found in the Seed_XCCDF Folder*****" 
   Write-Output "*****Script Execution Interrupted*****"
   exit
  }  
  if(([xml]$script:XCCDF | Measure-Object).Count -gt 1){
   Write-Output "*****More than one XCCDF file is located in the Seed_XCCDF Folder*****" 
   Write-Output "*****Script Execution Interrupted*****" 
   exit
  } 
}

function importXCCDFResults{
$ruleID=$null
for($i=0;$i -lt $script:XCCDF.Length;$i++){
  if($script:XCCDF[$i] -match "<cdf:rule-result"){
   $result=$script:XCCDF[$i] -match "SV-[0-9]+[r][0-9]+_rule" 
   $ruleID=$Matches.Values
   if($script:XCCDF[$i+1] -match "pass"){
    $status="NotAFinding"
   } else {$status="Open"}   
  write-output "Importing XCCDF result for: $ruleID"
  &updateVulnStatus $ruleID $status   
  } 
 }
 cls
}

function getInstalledSoftware{
$packages64 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion 
$packages32 = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion 
$script:installedSoftware = $packages32 + $packages64 
}

function getStigText{  
  #Load ckl file into memory in XML format
  $script:stigText=( Select-Xml -Path .\CKL\*.ckl -XPath / ).Node    
}

function saveUpdatedCkl{
  $Path = (join-path $pwd "\Reports\OS_$OSReleaseID`_MS_$computerName.ckl")
  $stigText.Save($Path)  
}

function getComputerName{
  $script:computerName=$env:COMPUTERNAME
}

function setScriptGlobalVariables{
&getStigText  
&getcomputerName
&getOSReleaseID
&loadXCCDF
&getInstalledSoftware


$script:isClassified=&getUserInputs "1.  Is this Server a classified system [y/n]?" `
      -valid_values ('Y', 'N')
$script:isVirtualMachine=&getUserInputs "2.  Is this OS a Virtual Instance of Windows Server 2012 [y/n]?" `
      -valid_values ('Y', 'N')
}

function runVulnerabilityChecks{
 $functionList=(Get-ChildItem function: | select-string -pattern "^V_")#get function names in script that start with V_ 
 $totalNumFunctions=($functionList | Measure-Object).Count
 foreach($function in $functionList){
  $functionCount=$functionCount + 1
  &$function #Calling all "V_" functions in script
  Write-Output "($functionCount/$totalNumFunctions) Check $function Complete"      
 }
}

function getUserInputs($question, $valid_values){
$found=0;

  if ( $valid_values.count -ge 1 ) {
    while ( $found -eq 0 ) {
      $response = read-host "$CR$CR$question"
      foreach ($line in $valid_values) {
        if ( $response -match "^$line$" ) {
          $found = 1;
        }
      }
    }
  } else {
    $response = read-host "$question"
  }
  $response.toupper();  
}

function CheckForRunAsAdmin{  
   $isRunAsAdmin=([Security.Principal.WindowsPrincipal] `
   [Security.Principal.WindowsIdentity]:: ` 
   GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 
   
   if(!$isRunAsAdmin){
    Write-Output "*****This Script Must Be Run As Administrator******"
    Write-Output "*******Script Execution Interrupted*******"
    exit
   }   
} 


function getOSReleaseID{
 $OScaption=Get-WmiObject -class Win32_OperatingSystem | select caption
 $script:OSReleaseID=$OScaption.caption 
}

##################################
#####END HELPER FUNCTIONS#########
##################################

##################################
#####START VULN CHECKS############
##################################

function V_1070{
&updateStigCommentsField "V-1070" `
      "This check requires a manual review."
}

function V_1072{
&updateStigCommentsField "V-1072" `
      "This check requires a manual review."
}

function V_1074{
$status="Not_Reviewed"
$softwareListing=$null
 foreach($package in $script:installedSoftware){
  if($package.DisplayName -match "McAfee VirusScan Enterprise"){
   $status="NotAFinding"
   break
  } else {
   $softwareListing=($softwareListing + $package.DisplayName + "`n")
  }  
 }
 if($status -eq "Not_Reviewed"){
  &updateStigCommentsField "V-1074" ("  McAfee VirusScan Enterprise was not detected. `
  Please review the below list of installed software on this server for an anti-virus program.`n" + `
  ($softwareListing))
 }
 &updateVulnStatus "V-1074" $status
}

function V_1076{
&updateStigCommentsField "V-1076" `
      "This check requires a manual review."
}

function V_1112{
$accounts
([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
$user = ([ADSI]$_.Path)
$lastLogin = $user.Properties.LastLogin.Value
$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
 if ($lastLogin -eq $null) {
 $lastLogin = 'Never'
 }
 $s=(("User Name: " + $user.Name + "`n" + "Last Login: " + $lastLogin + "`n" + "Enabled: "+ $enabled + "`n") + "`n") 
 $accounts=$accounts + $s
 }
 &updateStigCommentsField "V-1112" ("List of local accounts:`n" + $accounts)
}

function V_1127{
$properties=net localgroup Administrators 
&updateStigCommentsField "V-1127" ($properties | Out-String)
}

function V_1128{
&updateStigCommentsField "V-1128" `
      "This check requires a manual review."
}

function V_1135{
$status="Not_Reviewed"
$printers = Get-WmiObject -class Win32_Printer  
$printer = $printers | where-object {$_.shared}
 if(($printer | Measure-object).Count -eq 0){
  $status="Not_Applicable"
 } else {
  &updateStigCommentsField "V-1135" "One or more printer shares were detected on this server.  Perform a manual check."
 }
 &updateVulnStatus "V-1135" $status
}

function V_2907{
$status="Not_Reviewed"
$mpaa=$script:installedSoftware | Where-Object {$_.DisplayName -eq "McAfee Policy Auditor Agent"}
 if (($mpaa | Measure-Object).Count -gt 0) {
  if($mpaa.DisplayVersion -ge 5.2){
   $status="NotAFinding"
  } else {
   $status="Open"
   &updateStigCommentsField "V-2907" "McAfee Policy Auditor Agent is less than 5.2"
  }

 } else {
  &updateStigCommentsField "V-2907" "McAfee Policy Auditor Agent is not installed on this server."
  $status="Open"
 }
 &updateVulnStatus "V-2907" $status
}


function V_3245{
Write-Output "Searching for file shares.  Do not close this window."
&updateStigCommentsField "V-3245" ("File shares on this host:" + `
 (get-WmiObject -class Win32_Share | `
   Format-List -Property Name,Path,Description | Out-String))
}

function V_3289{
$status="Not_Reviewed"
$services=Get-Service | Where-Object {$_.Status -eq "Running"}
 foreach($service in $services){
  if($service.Name -eq "MpsSvc" -or $service.Name -eq "HipMgmt"){
   $status = "NotAFinding"
  } 
 }
 if($status -eq "Not_Reviewed"){
  &updateStigCommentsField "V-42420" ("  The McAfee HIPS service is not running.  Perform a manual check.")
 }
 &updateVulnStatus "V-3289" $status

}

function V_3472{
&updateStigCommentsField "V-3472" ("Type on this server: " + (W32tm /query /configuration | select-string "^Type"))
}

function V_3481{
$status="Not_Reviewed"
$location="HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer\"
$key="PreventCodecDownload"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-3481" $status 
}

function V_3487{
Get-Service | Where-Object {$_.Status -eq "Running"} | FL Name, DisplayName >> .\Temp\V-3487.txt
&updateStigCommentsField "V-3487" `
("Services running on this server: `n" + (Get-Content .\Temp\V-3487.txt | out-string))
Remove-Item .\Temp\V-3487.txt -ErrorAction SilentlyContinue 
}

function V_6840{
$accounts=Get-CimInstance -Class Win32_Useraccount -Filter `
"PasswordExpires=False and LocalAccount=True" | FL Name, PasswordExpires, Disabled, LocalAccount
 if(($accounts | Measure-object).Count -eq 0){
  $status="NotAFinding"
  &updateVulnStatus "V-6840" $status
 } else {
 Get-CimInstance -Class Win32_Useraccount -Filter `
 "PasswordExpires=False and LocalAccount=True" | FL Name, PasswordExpires, Disabled, LocalAccount >> .\Temp\V-6840.txt
 &updateStigCommentsField "V-6840" `
 ("Local accounts with PasswordExpires set to False: `n" + (Get-content .\Temp\V-6840.txt | out-string))
 }
Remove-Item .\Temp\V-6840.txt -ErrorAction SilentlyContinue
}

function V_1119{
$status="Not_Reviewed"
try{
 $bootLoaderEntries=bcdedit -ErrorAction SilentlyContinue | select-string "Windows Boot Loader"
 if (($bootLoaderEntries | Measure-Object).Count -gt 1) {
  $status = "Open"
 } else {
  $status = "NotAFinding"
 }
} catch {
  $status = "Not_Reviewed"
} Finally {$error.Clear()}
 &updateVulnStatus "V-1119" $status
}

function V_1120{
$msg="This server does not appear to be listening on TCP port 21 (FTP).  Perform a manual check. `nListening TCP ports on this host:`n"
$activeTCPPorts=Get-NetTCPConnection -State Listen 
 foreach ($port in $activeTCPPorts){
  if($port.LocalPort -eq "21"){
   $msg="This server appears to be listening on TCP port 21 (FTP).  Perform a manual check. `nListening TCP ports on this host:`n"
  } 
 }
 &updateStigCommentsField "V-1120" ($msg + ($activeTCPPorts.LocalPort | Out-String))
}

function V_1121{
$msg="This server does not appear to be listening on TCP port 21 (FTP).  Perform a manual check. `nListening TCP ports on this host:`n"
$activeTCPPorts=Get-NetTCPConnection -State Listen 
 foreach ($port in $activeTCPPorts){
  if($port.LocalPort -eq "21"){
   $msg="This server appears to be listening on TCP port 21 (FTP).  Perform a manual check. `nListening TCP ports on this host:`n"
  } 
 }
 &updateStigCommentsField "V-1121" ($msg + ($activeTCPPorts.LocalPort | Out-String))
}

function V_1168{
 $status="Not_Reviewed"
 net localgroup "Backup Operators" >> .\Temp\V-1168.txt 
 $actual=(Get-Content .\Temp\V-1168.txt)
 $template=(Get-Content .\Temp\V-1168_template.txt)
 $diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
 if(($diffCount | Measure-Object).Count -eq 0){
   $status = "Not_Applicable"  
 } else {
   $status = "Not_Reviewed"
   &updateStigCommentsField "V-1168" ($actual | Out-String)
 } 
 Remove-Item .\Temp\V-1168.txt -ErrorAction SilentlyContinue
 &updateVulnStatus "V-1168" $status    
}

function V_3337{
$status="Not_Reviewed"
$nameSpace="root\rsop\computer"
$query="select * from RSOP_SecuritySettingBoolean where `
           KeyName='LSAAnonymousNameLookup' and precedence='1'"
try{
 $properties=Get-WmiObject -namespace $nameSpace -Query $query -ErrorAction Stop
 if($properties.Setting -match "False"){
  $status = "NotAFinding"
 } else {
  $status = "Open"
 }
} catch {
   $status = "Not_Reviewed"   
 } Finally {$error.Clear()}
&updateVulnStatus "V-3337" $status
}

function V_14225{
$s=$null
$builtinAdmins=(net localgroup administrators).where({$_ -match '-{79}'},'skipuntil') -notmatch '-{79}|The command completed'
$results=$builtinAdmins -notmatch ".*\\.*"
 foreach($result in $results){
  if($result -ne ''){
   $s=$s + ("Account Name: " +  $result + "`n" + (Net User $result | Find /i "Password Last Set") + "`n")
  }
 }
 &updateStigCommentsField "V-14225" $s
}

function V_14268{
$status="Not_Reviewed"
$location="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
$key="SaveZoneInformation"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 2){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-14268" $status
}

function V_7002{
 Get-CimInstance -Class Win32_Useraccount -Filter `
 "PasswordRequired=False and LocalAccount=True" | FL Name, PasswordRequired, Disabled, LocalAccount >> .\Temp\V-7002.txt
 &updateStigCommentsField "V-7002" `
 ("Local accounts with PasswordRequired set to False: `n" + (Get-content .\Temp\V-7002.txt | out-string)) 
Remove-Item .\Temp\V-7002.txt -ErrorAction SilentlyContinue
}

function V_14269{
$status="Not_Reviewed"
$location="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
$key="HideZoneInfoOnProperties"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-14269" $status
}

function V_14270{
$status="Not_Reviewed"
$location="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
$key="ScanWithAntiVirus"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 3){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-14270" $status
}

function V_15727{
$status="Not_Reviewed"
$location="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"
$key="NoInPlaceSharing"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-15727" $status 
}

function V_16021{
$status="Not_Reviewed"
$location="HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\"
$key="NoImplicitFeedback"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-16021" $status
}

function V_16048{
$status="Not_Reviewed"
$location="HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0\"
$key="NoExplicitFeedback"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-16048" $status

}

function V_36451{
&updateStigCommentsField "V-36451" `
      "This check requires a manual review."
}

function V_36656{
$status="Not_Reviewed"
$location="HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\"
$key="ScreenSaveActive"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-36656" $status 
}

function V_36657{
$status="Not_Reviewed"
$location="HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\"
$key="ScreenSaverIsSecure"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-36657" $status 
}

function V_36658{
&updateStigCommentsField "V-36658" `
      "This check requires a manual review."
}

function V_36659{
&updateStigCommentsField "V-36659" `
      "This check requires a manual review."
}

function V_36661{
&updateStigCommentsField "V-36661" `
      "This check requires a manual review."
}

function V_36662{
&updateStigCommentsField "V-36662" `
      "This check requires a manual review."
}

function V_36666{
&updateStigCommentsField "V-36666" `
      "This check requires a manual review."
}

function V_36667{
$status="Not_Reviewed"
$location="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$key="SCENoApplyLegacyAuditPolicy"

if($script:isVirtualMachine -eq "N"){ 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key 
 if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
  $auditPolicyResults=AuditPol /get /category:"Object Access" | select-string -pattern `
                   "^\s Removable Storage" 
  if(($auditPolicyResults | select-string "Failure" | Measure-Object).Count -gt 0){
    $status = "NotAFinding"
  } else {
   $status = "Open"
  }
 } else {$status = "Open"}
} else {
  &updateStigCommentsField "V-36667" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-36667" $status 
}

function V_36668{
$status="Not_Reviewed"
$location="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$key="SCENoApplyLegacyAuditPolicy"

if($script:isVirtualMachine -eq "N"){ 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key 
 if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
  $auditPolicyResults=AuditPol /get /category:"Object Access" | select-string -pattern `
                   "^\s Removable Storage" 
  if(($auditPolicyResults | select-string "Success" | Measure-Object).Count -gt 0){
    $status = "NotAFinding"
  } else {
   $status = "Open"
  }
 } else {$status = "Open"}
} else {
  &updateStigCommentsField "V-36668" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-36668" $status
}

function V_36670{
&updateStigCommentsField "V-36670" `
      "This check requires a manual review."
}

function V_36671{
&updateStigCommentsField "V-36671" `
      "This check requires a manual review."
}

function V_36672{
&updateStigCommentsField "V-36672" `
      "This check requires a manual review."
}

function V_36710{
$status="Not_Reviewed"
 if(Test-Path -Path c:\Windows\WinStore){
  $index=$script:OSReleaseID.Indexof('R2')
  if($index -gt 0){
   $location="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\"
   $key="AutoDownload" 
   $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
    if ($items.$key.count -eq 1 -and $items.$key -eq 2){
     $status = "NotAFinding"    
    } else {
     $status = "Open"
    }
  } else {
   $location="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\WindowsUpdate\"
   $key="AutoDownload" 
   $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
    if ($items.$key.count -eq 1 -and $items.$key -eq 2){
     $status = "NotAFinding"    
    } else {
     $status = "Open"
    }
  }
 }else {
  $status="Not_Applicable"
 }
 &updateVulnStatus "V-36710" $status
}

function V_36711{
$status="Not_Reviewed"
$pathExists=Test-Path C:\Windows\WinStore -PathType Container

if($pathExists -eq "True"){
 $location="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\"
 $key="RemoveWindowsStore"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
} else {
 $status="Not_Applicable"
}
&updateVulnStatus "V-36711" $status
}

function V_36722{
$status="Not_Reviewed"
$sysRoot=Get-Item Env:SystemRoot
$Path=(join-path $sysRoot.Value "\SYSTEM32\WINEVT\LOGS\Application.evtx")
try{
 (get-acl $Path).access | ft IdentityReference,FileSystemRights -auto -ErrorAction Stop >> .\Temp\V-36722.txt
 $actual=(Get-Content .\Temp\V-36722.txt) 
 $template=(Get-Content .\Temp\V-36722_template.txt)
 $diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
 if(($diffCount | Measure-Object).Count -eq 0){
  $status = "NotAFinding"  
 } else {
  $status = "Open"
 } 
} catch {
   $status = "Not_Reviewed"
   &updateStigCommentsField "V-36722" `
      "Application.evtx was not found in the default location.  Perform a manual check."
} Finally {$error.Clear()}
Remove-Item .\Temp\V-36722.txt -ErrorAction SilentlyContinue
&updateVulnStatus "V-36722" $status
}

function V_36723{
$status="Not_Reviewed"
$sysRoot=Get-Item Env:SystemRoot
$Path=(join-path $sysRoot.Value "\SYSTEM32\WINEVT\LOGS\Security.evtx")
try{
 (get-acl $Path).access | ft IdentityReference,FileSystemRights -auto -ErrorAction Stop >> .\Temp\V-36723.txt
 $actual=(Get-Content .\Temp\V-36723.txt) 
 $template=(Get-Content .\Temp\V-36723_template.txt)
 $diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
 if(($diffCount | Measure-Object).Count -eq 0){
  $status = "NotAFinding"  
 } else {
  $status = "Open"
 } 
} catch {
   $status = "Not_Reviewed"
   &updateStigCommentsField "V-36723" `
      "Security.evtx was not found in the default location.  Perform a manual check."
} Finally {$error.Clear()}
Remove-Item .\Temp\V-36723.txt -ErrorAction SilentlyContinue
&updateVulnStatus "V-36723" $status
}

function V_36724{
$status="Not_Reviewed"
$sysRoot=Get-Item Env:SystemRoot
$Path=(join-path $sysRoot.Value "\SYSTEM32\WINEVT\LOGS\System.evtx")
try{
 (get-acl $Path).access | ft IdentityReference,FileSystemRights -auto -ErrorAction Stop >> .\Temp\V-36724.txt
 $actual=(Get-Content .\Temp\V-36724.txt) 
 $template=(Get-Content .\Temp\V-36724_template.txt)
 $diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
 if(($diffCount | Measure-Object).Count -eq 0){
  $status = "NotAFinding"  
} else {
 $status = "Open"
} 
} catch {
   $status = "Not_Reviewed"
   &updateStigCommentsField "V-36724" `
      "System.evtx was not found in the default location.  Perform a manual check."
} Finally {$error.Clear()}
Remove-Item .\Temp\V-36724.txt -ErrorAction SilentlyContinue
&updateVulnStatus "V-36724" $status
}

function V_36733{
&updateStigCommentsField "V-36733" `
      "This check requires a manual review."
}

function V_36734{
&updateStigCommentsField "V-36734" `
("Review the below list of McAfee services to determine if this host is compliant or non-compliant.`nAt a minimum, you should see the McAfee Agent Service or the McAfee Framework Service
running on this host. `n" + (get-service | select-object DisplayName, Status `
 | select-string -pattern "Mcafee" | out-string)) 
}

function V_36735{
&updateStigCommentsField "V-36735" `
      "This check requires a manual review."
}

function V_36736{
$status="Not_Reviewed"
$ca=certutil | select-string -pattern "\s Name:"
 if(($ca | Measure-Object).Count -gt 0){
  $status = "NotAFinding" 
 } else {
  $status = "Open"
 }
&updateVulnStatus "V-36736" $status
}

function V_36776{
$status="Not_Reviewed"
$location="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"
$key="NoCloudApplicationNotification"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-36776" $status 
}

function V_36777{
$status="Not_Reviewed"
$location="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"
$key="NoToastApplicationNotificationOnLockScreen"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-36777" $status 
}

function V_40172{
&updateStigCommentsField "V-40172" `
      "This check requires a manual review."
}

function V_40173{
&updateStigCommentsField "V-40173" `
      "This check requires a manual review."
}

function V_40177{
$status="Not_Reviewed"
$location="HKLM:\System\CurrentControlSet\Control\Lsa\"
$key="EveryoneIncludesAnonymous"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 0){
    icacls "c:\program files" >> .\Temp\V-40177.txt
    icacls "c:\program files (x86)" >> .\Temp\V-40177.txt
    $actual=(Get-Content .\Temp\V-40177.txt)
    $template=(Get-Content .\Temp\V-40177_template.txt)
    $diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
    if(($diffCount | Measure-Object).Count -eq 0){
     $status = "NotAFinding"  
    } else {
     $status = "Open"
    }     
  } else {
    $status = "Open"
  }
  Remove-Item .\Temp\V-40177.txt -ErrorAction SilentlyContinue
  &updateVulnStatus "V-40177" $status
}

function V_40178{
$status="Not_Reviewed"
$location="HKLM:\System\CurrentControlSet\Control\Lsa\"
$key="EveryoneIncludesAnonymous"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 0){
    icacls c:\ >> .\Temp\V-40178.txt
    $actual=(Get-Content .\Temp\V-40178.txt)
    $template=(Get-Content .\Temp\V-40178_template.txt)
    $diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
    if(($diffCount | Measure-Object).Count -eq 0){
     $status = "NotAFinding"  
    } else {
     $status = "Open"
    }     
  } else {
    $status = "Open"
  }
  Remove-Item .\Temp\V-40178.txt -ErrorAction SilentlyContinue
  &updateVulnStatus "V-40178" $status
}

function V_40179{
$status="Not_Reviewed"
$location="HKLM:\System\CurrentControlSet\Control\Lsa\"
$key="EveryoneIncludesAnonymous"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 0){
    icacls c:\windows >> .\Temp\V-40179.txt
    $actual=(Get-Content .\Temp\V-40179.txt)
    $template=(Get-Content .\Temp\V-40179_template.txt)
    $diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
    if(($diffCount | Measure-Object).Count -eq 0){
     $status = "NotAFinding"  
    } else {
     $status = "Open"
    }     
  } else {
    $status = "Open"
  }
  Remove-Item .\Temp\V-40179.txt -ErrorAction SilentlyContinue
  &updateVulnStatus "V-40179" $status
}

function V_40198{
&updateStigCommentsField "V-40198" `
      "This check requires a manual review."
}

function V_40200{
$status="Not_Reviewed"
$location="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$key="SCENoApplyLegacyAuditPolicy"
 
$items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key

if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
 $auditPolicyResults=AuditPol /get /category:"Object Access" | select-string -pattern `
                   "^\s Central Policy Staging" 
 if(($auditPolicyResults | select-string "Failure" | Measure-Object).Count -gt 0){
   $status = "NotAFinding"
 } else {
   $status = "Open"
 }
} else {$status = "Open"}
&updateVulnStatus "V-40200" $status
}

function V_40202{
$status="Not_Reviewed"
$location="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$key="SCENoApplyLegacyAuditPolicy"
 
$items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key

if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
 $auditPolicyResults=AuditPol /get /category:"Object Access" | select-string -pattern `
                   "^\s Central Policy Staging" 
 if(($auditPolicyResults | select-string "Success" | Measure-Object).Count -gt 0){
   $status = "NotAFinding"
 } else {
   $status = "Open"
 }
} else {$status = "Open"}
&updateVulnStatus "V-40202" $status
}

function V_40204{
$status="Not_Reviewed"
$location="HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"
$key="RedirectOnlyDefaultClientPrinter"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-40204" $status 
}

function V_42420{
$status="Not_Reviewed"
$services=Get-Service | Where-Object {$_.Status -eq "Running"}
 foreach($service in $services){
  if($service.Name -eq "MpsSvc" -or $service.Name -eq "mfefire"){
   $status = "NotAFinding"
  } 
 }
 if($status -eq "Not_Reviewed"){
  &updateStigCommentsField "V-42420" ("  No enabled firewall was detected.  Perform a manual check.")
 }
 &updateVulnStatus "V-42420" $status
}

function V_43238{
$status="Not_Reviewed"
$index=$script:OSReleaseID.Indexof('R2')
if($index -gt 0){
 $location="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
 $key="NoLockScreenSlideshow" 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
} else {
 $status="Not_Applicable"
}
&updateVulnStatus "V-43238" $status
}

function V_43240{
$status="Not_Reviewed"
$index=$script:OSReleaseID.Indexof('R2')
if($index -gt 0){
 $location="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\"
 $key="DontDisplayNetworkSelectionUI" 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
} else {
 $status="Not_Applicable"
}
&updateVulnStatus "V-43240" $status
}

function V_43241{
$status="Not_Reviewed"
$index=$script:OSReleaseID.Indexof('R2')
if($index -gt 0){
 $location="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
 $key="MSAOptional" 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
} else {
 $status="Not_Applicable"
}
&updateVulnStatus "V-43241" $status
}

function V_43245{
$status="Not_Reviewed"
$index=$script:OSReleaseID.Indexof('R2')
if($index -gt 0){
 $location="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\"
 $key="DisableAutomaticRestartSignOn" 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
} else {
 $status="Not_Applicable"
}
&updateVulnStatus "V-43245" $status
}

function V_57637{
$status="Not_Reviewed"
if($script:isClassified -eq "N"){
 Get-AppLockerPolicy -Effective -XML > .\Temp\V-57637.xml
 $appLockerText=(Select-Xml -Path .\Temp\V-57637.xml -XPath / ).Node
 $appLockerText.AppLockerPolicy.RuleCollection.FilePathRule >> .\Temp\V-57637.txt
 $appLockerText.AppLockerPolicy.RuleCollection.FilePublisherRule >> .\Temp\V-57637.txt
 $appLockerText.AppLockerPolicy.RuleCollection.FileHashRule >> .\Temp\V-57637.txt
 Remove-Item .\Temp\V-57637.xml -ErrorAction SilentlyContinue
 &updateStigCommentsField "V-57637" `
 ("Current ApplLocker Rules on this Host (If no rules are listed, then Applocker is not configured):" + `
 (Get-Content .\Temp\V-57637.txt | Out-String))
 Remove-Item .\Temp\V-57637.txt -ErrorAction SilentlyContinue
 } else {
  $status="Not_Applicable"
 }
 &updateVulnStatus "V-57637" $status
}

function V_57641{
&updateStigCommentsField "V-57641" `
      "This check requires a manual review."
}

function V_57645{
&updateStigCommentsField "V-57645" `
      "This check requires a manual review."
}

function V_57653{
&updateStigCommentsField "V-57653" `
      "This check requires a manual review."
}

function V_57655{
&updateStigCommentsField "V-57655" `
      "This check requires a manual review."
}

function V_57719{
&updateStigCommentsField "V-57719" `
      "This check requires a manual review."
}

function V_72753{
$status="Not_Reviewed"
$location="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\"
$key="UseLogonCredential"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 0){
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-72753" $status 
}

function V_75915{
$status="Not_Reviewed"
$orphanedSIDCount=0
try{
  secedit /export /areas USER_RIGHTS /cfg .\Temp\SECEDIT.txt /quiet 
  $orphanedSIDCount=Get-Content -Path .\Temp\SECEDIT.txt -ErrorAction Stop | Where-Object {$_ -like '*S-1-…'}
  if (($orphanedSIDCount | Measure-Object).Count -gt 0){
    $status = "Open"
  } else { $status = "NotAFinding" }
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
 &updateVulnStatus "V-75915" $status
Remove-Item .\Temp\SECEDIT.txt -ErrorAction SilentlyContinue
}

function V_80473{
$status="Not_Reviewed"
$index=$script:OSReleaseID.Indexof('R2')
 if($index -gt 0){
  $status = "NotAFinding"
 } else {
   if($PSVersionTable.PSVersion.Major -lt 4){
    $status = "Open"
   } else { $status = "NotAFinding"}
 }
 &updateVulnStatus "V-80473" $status
}

function V_80475{
$status="Not_Reviewed"
$regStatus=$null
$hotFixStatus=$null
$HotFixIDs=Get-HotFix | select HotFixID
$location="HKLM:\SOFTWARE\ Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"
$key="EnableScriptBlockLogging"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ($items.$key.count -eq 1 -and $items.$key -eq 1){
    $regStatus = $true    
  } else {
    $regStatus = $false
  }

 $index=$script:OSReleaseID.Indexof('R2')
 if($index -gt 0){ #Windows 2012 R2
 foreach($HotFixID in $HotFixIDs){
  if($HotFixID -match "KB3000850"){
   $hotFixStatus=$true
  } else {
   $hotFixStatus=$false
  }
 }
  if($PSVersionTable.PSVersion.Major -lt 5){
    if($regStatus -eq $true -and $hotFixStatus -eq $true){
     $status = "NotAFinding"
    } else {
     $status = "Open"
    }
  } else {
    if($regStatus -eq $true){
     $status = "NotAFinding"
    } else {
     $status = "Open"
    }
  } 
 } else { #Windows 2012 Standard
 foreach($HotFixID in $HotFixIDs){
  if($HotFixID -match "KB3119938 "){
   $hotFixStatus=$true
  } else {
   $hotFixStatus=$false
  }
 }
 if($regStatus -eq $true -and $PSVersionTable.PSVersion.Major -lt 4 ){
  $status = "Open"
 }
 if($PSVersionTable.PSVersion.Major -lt 5 -and $PSVersionTable.PSVersion.Major -ge 4){
    if($regStatus -eq $true -and $hotFixStatus -eq $true){
     $status = "NotAFinding"
    } else {
     $status = "Open"
    }
  } else {
    if($regStatus -eq $true -and $PSVersionTable.PSVersion.Major -ge 5 ){
     $status = "NotAFinding"
    } else {
     $status = "Open"
    }
  } 
 }
 &updateVulnStatus "V-80475" $status
}

##################################
#####END VULN CHECKS##############
##################################


#####>main()<##########
cls
&CheckForRunAsAdmin 
cd..
&setScriptGlobalVariables
cls
Write-Output "Starting Checks of Not Reviewed STIG Items.  Do not close this window."
&runVulnerabilityChecks
cls
Write-Output "Importing XCCDF Results.  Do not close this window."
&importXCCDFResults
&saveUpdatedCkl
cls
Write-Output "Script executed successfully."
Write-Output ("The updated CKL is located here: " + (Get-Location) + "\Reports")
#####END main()#####
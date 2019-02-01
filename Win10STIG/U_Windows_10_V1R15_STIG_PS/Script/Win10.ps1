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
$script:isMobileSystem=$null #Holds Boolean Determination if system is mobile

######################################
#####END SCRIPT SCOPE VARIABLES#######
######################################

################################
#####START HELPER FUNCTIONS#####
################################

function updateVulnStatus([string]$vulID,[string]$status){
  $vuln=$null 
  try{
   $Vuln=$stigText.CHECKLIST.STIGS.iSTIG.VULN | 
       Where-Object {$_.STIG_DATA.ATTRIBUTE_DATA -eq $vulID} 
   $Vuln.STATUS=$status 
  } catch {      
  } Finally {$error.Clear()}
}

function updateStigCommentsField([string]$vulID,[string]$commentText){
  $comments=$null
  try{
   $comments=$stigText.CHECKLIST.STIGS.iSTIG.VULN | 
       Where-Object {$_.STIG_DATA.ATTRIBUTE_DATA -eq $vulID}
   $comments.FINDING_DETAILS=$commentText    
  } catch {      
  } Finally {$error.Clear()}
}

function getStigText{  
  #Load ckl file into memory in XML format
  $script:stigText=( Select-Xml -Path .\CKL\*.ckl -XPath / ).Node  
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
}

function saveUpdatedCkl{
  $Path = (join-path $pwd "\Reports\OS_Windows_10_$computerName.ckl")
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
$script:isClassified=&getUserInputs "1.  Is this host a classified system [y/n]?" `
      -valid_values ('Y', 'N') 
$script:isStandAlone=&getUserInputs "2.  Is this host a stand-alone system [y/n]?" `
      -valid_values ('Y', 'N')   
$script:isVirtualMachine=&getUserInputs "3.  Is this OS a Virtual Desktop Instance of Windows 10 [y/n]?" `
      -valid_values ('Y', 'N')
$script:isMobileSystem=&getUserInputs "4.  Is this a mobile system (laptop, tablet) [y/n]?" `
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
 $location="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
 $key="ReleaseId"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
 $script:OSReleaseID=$items.$key
}

##################################
#####END HELPER FUNCTIONS#########
##################################

##################################
#####START VULN CHECKS############
##################################

function V_63323{
$status="Not_Reviewed"
if($script:isVirtualMachine -eq "N"){
 if($script:isStandAlone -eq "N"){
  $tpmDetails= Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm
   if($tpmDetails.IsActivated_InitialValue -match "True" -and `
      $tpmDetails.IsEnabled_InitialValue -match "True" -and `
      $tpmDetails.IsOwned_InitialValue -match "True" -and `
      ($tpmDetails.SpecVersion -match "2.0" -or $tpmDetails.SpecVersion -match "1.2")){
       $status = "NotAFinding"
   } else {
     $status = "Open"
   }
 } else {
  $status = "Not_Applicable"
 }
} else {
 $status="Not_Reviewed" 
 &updateStigCommentsField "V-63323" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-63323" $status 
}

function V_63337{
#VolumeType = 0 --OS Volume
#VolumeType = 1 --Fixed Data Volume
#VolumeType = 2 --Portable Data Volume
$volume=$null
$baseVolumeState=$null
$nameSpace="Root\cimv2\security\MicrosoftVolumeEncryption"
$baseQuery="select * from win32_Encryptablevolume where `
           (VolumeType='0' or VolumeType='1')"
$query="select * from win32_Encryptablevolume where `
           (VolumeType='0' or VolumeType='1') and (ProtectionStatus='0')"
if($script:isMobileSystem -eq "Y"){ 
 try{
   $baseVolumeState=Get-WmiObject -namespace $nameSpace -Query $baseQuery -ErrorAction Stop
   if (($baseVolumeState | Measure-Object).Count -gt 0) {
    $volume=Get-WmiObject -namespace $nameSpace -Query $query -ErrorAction Stop    
    if (($volume | Measure-Object).Count -gt 0) {
       $status = "Open"
      &updateStigCommentsField "V-63337" `
      ("Drive that is unencrypted: " + $volume.DriveLetter)       
     } else {
       $status = "NotAFinding"
     } 
   } else {$status="Not_Reviewed"}
 } catch {
   $status = "Not_Reviewed"   
 } Finally {$error.Clear()}
} else {
 $status = "Not_Applicable"
}
 &updateVulnStatus "V-63337" $status  
}

function V_63343{
&updateStigCommentsField "V-63343" `
("Review the below list of McAfee services to determine if this host is compliant or non-compliant.`nAt a minimum, you should see the McAfee Agent Service or the McAfee Framework Service
running on this host. `n" + (get-service | select-object DisplayName, Status `
 | select-string -pattern "Mcafee" | out-string)) 
}

function V_63345{
Remove-Item .\Temp\V-63345.xml -ErrorAction SilentlyContinue
Get-AppLockerPolicy -Effective -XML > .\Temp\V-63345.xml
$appLockerText=(Select-Xml -Path .\Temp\V-63345.xml -XPath / ).Node
$appLockerText.AppLockerPolicy.RuleCollection.FilePathRule >> .\Temp\V-63345.txt
$appLockerText.AppLockerPolicy.RuleCollection.FilePublisherRule >> .\Temp\V-63345.txt
$appLockerText.AppLockerPolicy.RuleCollection.FileHashRule >> .\Temp\V-63345.txt
Remove-Item .\Temp\V-63345.xml -ErrorAction SilentlyContinue
&updateStigCommentsField "V-63345" `
("Current ApplLocker Rules on this Host (If no rules are listed, then Applocker is not configured):" + `
  (Get-Content .\Temp\V-63345.txt | Out-String))
Remove-Item .\Temp\V-63345.txt -ErrorAction SilentlyContinue
}

function V_63351{
$status="Not_Reviewed"
$AVProduct=$null
$productState=$null
$nameSpace="root/SecurityCenter2"
$query="select * from AntivirusProduct" 

$AVProduct=Get-CimInstance -Namespace $nameSpace -Query $query `
            -ErrorAction Stop
 try{
 if (($AVProduct | Measure-Object).Count -eq 0) {
      $status = "Open"
    } else {
      $status = "NotAFinding"          
      &updateStigCommentsField "V-63351" `
      ("Antiviral Software Installed On This Host:`n" `
      + ($AVProduct.displayName | Out-String).Trim())
    }
 } catch {
   $status = "Not_Reviewed"
 } Finally {$error.Clear()}   
 &updateVulnStatus "V-63351" $status   
}

function V_63355{
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
 &updateVulnStatus "V-63355" $status
}

function V_63357{
Write-Output "Searching for file shares.  Do not close this window."
&updateStigCommentsField "V-63357" ("File shares on this host:" + `
 (get-WmiObject -class Win32_Share | `
   Format-List -Property Name,Path,Description | Out-String))  
}

function V_63359{
Remove-Item .\Temp\V-63359.txt -ErrorAction SilentlyContinue

([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where { $_.SchemaClassName -eq 'user' } | ForEach {
$user = ([ADSI]$_.Path)
$lastLogin = $user.Properties.LastLogin.Value
$enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
if ($lastLogin -eq $null) {
$lastLogin = 'Never'
}

"Account Name: " + $user.Name >> .\Temp\V-63359.txt
"Last Login: " + $lastLogin >> .\Temp\V-63359.txt
"Enabled: " + $enabled >> .\Temp\V-63359.txt
"`n" >> .\Temp\V-63359.txt
}
&updateStigCommentsField "V-63359" ("Local accounts on this host:`n" + `
            (Get-Content .\Temp\V-63359.txt | Out-String))
Remove-Item .\Temp\V-63359.txt -ErrorAction SilentlyContinue  
}

function V_63361{
$properties=net localgroup Administrators 
&updateStigCommentsField "V-63361" ($properties | Out-String)
 
}

function V_63363{
$properties=net localgroup "Backup Operators"
&updateStigCommentsField "V-63363" ($properties | Out-String)
}

function V_63367{ 
&updateStigCommentsField "V-63367" `
("Local user accounts on this host:`n" + (Get-LocalUser |` 
    Format-List -Property Name, Enabled, Description | Out-String))
}

function V_63373{
$status="Not_Reviewed"
icacls c:\ >> .\Temp\V-63373.txt
icacls "c:\program files" >> .\Temp\V-63373.txt
icacls c:\windows >> .\Temp\V-63373.txt
$actual=(Get-Content .\Temp\V-63373.txt)
$template=(Get-Content .\Temp\V-63373_template.txt)
$diffCount=Compare-Object $actual $template | ForEach-Object { $_.InputObject }
if(($diffCount | Measure-Object).Count -eq 0){
 $status = "NotAFinding"  
} else {
 $status = "Open"
} 
Remove-Item .\Temp\V-63373.txt -ErrorAction SilentlyContinue
&updateVulnStatus "V-63373" $status
}

function V_63393{
&updateStigCommentsField "V-63393" `
 ("Requires Manual Verification")
}

function V_63399{
$status="Not_Reviewed"
$properties=get-service | select-object DisplayName, Status `
 | select-string -pattern "Firewall"
$runningFirewall=$properties |select-string -pattern "Running"
if(($runningFirewall | Measure-Object).Count -eq 0){
 $status = "Open"  
} else {
 $status = "NotAFinding"
} 
 &updateVulnStatus "V-63399" $status
 &updateStigCommentsField "V-63399" `
("Status of Firewall Service(s) on this Host:`n" + ($properties | Out-String))
}

function V_63403{
 &updateStigCommentsField "V-63403" `
 ("Requires Manual Verification")
}

function V_63451{ 
$status="Not_Reviewed"
$location="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$key="SCENoApplyLegacyAuditPolicy"
 
$items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key

if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
 $auditPolicyResults=AuditPol /get /category:"Detailed Tracking" | select-string -pattern `
                   "^\s Plug and Play Events" 
 if(($auditPolicyResults | select-string "Success" | Measure-Object).Count -gt 0){
   $status = "NotAFinding"
 } else {
   $status = "Open"
 }
} else {$status = "Open"}
&updateVulnStatus "V-63451" $status
}

function V_63457{ 
$status="Not_Reviewed"
$location="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
$key="SCENoApplyLegacyAuditPolicy"
 
$items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key

if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
 $auditPolicyResults=AuditPol /get /category:"Logon/Logoff" | select-string -pattern `
                   "^\s Group Membership" 
 if(($auditPolicyResults | select-string "Success" | Measure-Object).Count -gt 0){
   $status = "NotAFinding"
 } else {
   $status = "Open"
 }
} else {$status = "Open"}
&updateVulnStatus "V-63457" $status
}

function V_63471{
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
  &updateStigCommentsField "V-63471" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-63471" $status
}

function V_63473{
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
  &updateStigCommentsField "V-63473" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-63473" $status
}

function V_63545{
$status="Not_Reviewed"
$location="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\"
$key="NoLockScreenCamera"

$PnPItems=Get-CimInstance -ClassName Win32_PnPEntity | select PnPClass
if($PnPItems.PnPClass -eq "Camera"){
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
 if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
   $status = "NotAFinding"
 } else {$status = "Open"}
} else {
  $status = "Not_Applicable"
} 
&updateVulnStatus "V-63545" $status
}

function V_63579{
$status="Not_Reviewed"
if($isClassified -eq "N"){
  try{
   $cert=Get-ChildItem -Path Cert:Localmachine\root -ErrorAction SilentlyContinue `
         | Where Subject -Like "*DoD*"  
    if(($cert.Subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561") ` -and 
       ($cert.Subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "D73CA91102A2204A36459ED32213B467D7CE97FB") ` -and
       ($cert.Subject -eq "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "B8269F25DBD937ECAFD4C35A9838571723F2D026") ` -and
       ($cert.Subject -eq "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "4ECB5CC3095670454DA1CBD410FC921F46B8564B")){
     $status = "NotAFinding" 
    } else {$status = "Open"}
   } catch {
    $status = "Not_Reviewed"
   } Finally {$error.Clear()}
} else {$status = "Not_Applicable"}
 &updateVulnStatus "V-63579" $status
}

function V_63583{
$status="Not_Reviewed"
if($isClassified -eq "N"){
  try{
   $cert=Get-ChildItem -Path Cert:Localmachine\root -ErrorAction SilentlyContinue `
         | Where Subject -Like "*ECA*"  
    if(($cert.Subject -eq "CN=ECA Root CA 2, OU=ECA, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "C313F919A6ED4E0E8451AFA930FB419A20F181E4") ` -and 
       ($cert.Subject -eq "CN=ECA Root CA 4, OU=ECA, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582")){
     $status = "NotAFinding" 
    } else {$status = "Open"}
   } catch {
    $status = "Not_Reviewed"
   } Finally {$error.Clear()}
} else {$status = "Not_Applicable"}
 &updateVulnStatus "V-63583" $status
}

function V_63587{
$status="Not_Reviewed"
if($isClassified -eq "N"){
  try{
   $cert=Get-ChildItem -Path Cert:Localmachine\disallowed -ErrorAction SilentlyContinue `
         | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"}   
    if(($cert.Subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "22BBE981F0694D246CC1472ED2B021DC8540A22F" -and `
          $cert.Issuer -eq "CN=DoD Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US") -and 
       ($cert.Subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "FFAD03329B9E527A43EEC66A56F9CBB5393E6E13" -and ` 
          $cert.Issuer -eq "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US") -and
       ($cert.Subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "FCE1B1E25374DD94F5935BEB86CA643D8C8D1FF4" -and ` 
          $cert.Issuer -eq "CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US")){
     $status = "NotAFinding" 
    } else {$status = "Open"}
   } catch {
    $status = "Not_Reviewed"
   } Finally {$error.Clear()}
} else {$status = "Not_Applicable"}
 &updateVulnStatus "V-63587" $status
}

function V_63589{
$status="Not_Reviewed"
if($isClassified -eq "N"){
  try{
   $cert=Get-ChildItem -Path Cert:Localmachine\disallowed -ErrorAction SilentlyContinue `
         | Where Issuer -Like "*CCEB Interoperability*"    
    if(($cert.Subject -eq "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3" -and `
          $cert.Issuer -eq "CN=US DoD CCEB Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US") -and 
       ($cert.Subject -eq "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US" `
     -and $cert.Thumbprint -eq "929BF3196896994C0A201DF4A5B71F603FEFBF2E" -and ` 
          $cert.Issuer -eq "CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US")){
     $status = "NotAFinding" 
    } else {$status = "Open"}
   } catch {
    $status = "Not_Reviewed"
   } Finally {$error.Clear()}
} else {$status = "Not_Applicable"}
 &updateVulnStatus "V-63589" $status
}

function V_63593{
&updateStigCommentsField "V-63593" `
      "Requires Manual Verification"
}

function V_63595{
$status="Not_Reviewed"
 if($script:isVirtualMachine -eq "N"){
  try{
   $properties=Get-CimInstance -ClassName Win32_DeviceGuard `
     -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
   if($properties.RequiredSecurityProperties -match "2" -and ` 
      $properties.VirtualizationBasedSecurityStatus -match "2"){
    $status = "NotAFinding" 
   } else {
    $status = "Open" 
   }
  } catch {
    $status = "Not_Reviewed"
  } Finally {$error.Clear()}
} else {
 &updateStigCommentsField "V-63595" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-63595" $status
}

function V_63599{
$status="Not_Reviewed"
if($script:isVirtualMachine -eq "N"){
  try{
   $properties=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace `
               root\Microsoft\Windows\DeviceGuard -ErrorAction Stop    
   if($properties.SecurityServicesRunning -match "1"){
    $status = "NotAFinding" 
   } else {
    $status = "Open" 
   }
  } catch {
    $status = "Not_Reviewed"
  } Finally {$error.Clear()}
} else {
 &updateStigCommentsField "V-63599" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-63599" $status
}

function V_63603{
$status="Not_Reviewed"
if($script:isVirtualMachine -eq "N"){
  try{
   $properties=Get-CimInstance -ClassName Win32_DeviceGuard -Namespace `
               root\Microsoft\Windows\DeviceGuard -ErrorAction Stop    
   if($properties.SecurityServicesRunning -match "2"){
    $status = "NotAFinding" 
   } else {
    $status = "Open" 
   }
  } catch {
    $status = "Not_Reviewed"
  } Finally {$error.Clear()}
} else {
 &updateStigCommentsField "V-63603" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-63603" $status
}

function V_63717{
$status="Not_Reviewed"
$location="HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\"
$key="RequireSecurityDevice"

if($script:isVirtualMachine -eq "N"){ 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key 
 if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
   $status = "NotAFinding"
 } else {
   $status = "Open"
 }  
} else {
  &updateStigCommentsField "V-63717" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
}
&updateVulnStatus "V-63717" $status
}

function V_63739{
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
&updateVulnStatus "V-63739" $status
}

function V_63839{
$status="Not_Reviewed"
$location="HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"
$key="NoToastApplicationNotificationOnLockScreen"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-63839" $status 
}

function V_63841{
$status="Not_Reviewed"
$location="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\"
$key="SaveZoneInformation"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 2) {
    $status = "NotAFinding"    
  } elseif ($items.$key.count -eq 1 -and $items.$key -eq 1){ 
    $status = "Open"    
  } elseif ($items.$key.count -eq 0){ 
    $status = "NotAFinding"
  }        
 &updateVulnStatus "V-63841" $status 
}

function V_68849{
$status="Not_Reviewed"
 if($OSReleaseID -gt 0){
  if($OSReleaseID -lt 1709){
    $location="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\"
    $key="DisableExceptionChainValidation"
 
    $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
    if ( $items.$key.count -eq 1 -and $items.$key -eq 0) {
      $status = "NotAFinding"    
    } else {
      $status = "Open"     
    }  
  } else {
    $status="Not_Applicable"
  }
 } else {
   $status="Not_Reviewed"
 }
&updateVulnStatus "V-68849" $status
}

function V_72765{
$status="Not_Reviewed"
$blueToothService=Get-Service bthserv | select Status
if($blueToothService.Status -eq "Stopped"){
 $status="Not_Applicable"
} else {
 &updateStigCommentsField "V-72765" `
      "The Bluetooth Service Appears to be running.  Perform a Mannual Check."
      $status="Not_Reviewed"
}
&updateVulnStatus "V-72765" $status
}

function V_72767{
$status="Not_Reviewed"
$blueToothService=Get-Service bthserv | select Status
if($blueToothService.Status -eq "Stopped"){
 $status="Not_Applicable"
} else {
 &updateStigCommentsField "V-72767" `
      "The Bluetooth Service Appears to be running.  Perform a Mannual Check."
      $status="Not_Reviewed"
}
&updateVulnStatus "V-72767" $status
}

function V_72769{
$status="Not_Reviewed"
$blueToothService=Get-Service bthserv | select Status
if($blueToothService.Status -eq "Stopped"){
 $status="Not_Applicable"
} else {
 &updateStigCommentsField "V-72769" `
      "The Bluetooth Service Appears to be running.  Perform a Mannual Check."
       $status="Not_Reviewed"
}
&updateVulnStatus "V-72769" $status
}

function V_74413{
$status="Not_Reviewed"
$location="HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\"
$key="EccCurves"
  
  $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key  
  if ( $items.$key.count -eq 2 -and $items.$key[0] -eq "NistP256" ` -and 
         $items.$key[1] -eq "NistP384") {
     $status = "NotAFinding"    
   } else {
     $status = "Open"     
   } 
 &updateVulnStatus "V-74413" $status
}

function V_76505{
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
 &updateVulnStatus "V-76505" $status
Remove-Item .\Temp\SECEDIT.txt -ErrorAction SilentlyContinue
}

function V_77083{
if($script:isVirtualMachine -eq "N"){
 try{
  $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction Stop  
  if($secureBootStatus -eq $true -or $secureBootStatus -eq $false){ 
   $status="NotAFinding" 
  } else { 
   $status = "Open"
  }
 } catch {
   $status = "Not_Reviewed"
 } Finally {$error.Clear()}
} else {
 &updateStigCommentsField "V-77083" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
 $status="Not_Reviewed"
}
  &updateVulnStatus "V-77083" $status
}

function V_77085{
if($script:isVirtualMachine -eq "N"){
 try{
  $secureBootStatus = Confirm-SecureBootUEFI -ErrorAction Stop  
  if($secureBootStatus -eq $true){ 
   $status="NotAFinding" 
  } else { 
   $status = "Open"
  }
 } catch {
   $status = "Not_Reviewed"
 } Finally {$error.Clear()}
} else {
 &updateStigCommentsField "V-77085" `
      "This Appears to be a Virtual Machine.  Perform a Mannual Check."
 $status="Not_Reviewed"
}
 &updateVulnStatus "V-77085" $status
}

function V_77091{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -System -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "OFF"){
   $status = "Open"
   } else {$status = "NotAFinding"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77091" $status
}

function V_77095{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -System -ErrorAction Stop
  if($processMitigation.ASLR.BottomUp -eq "OFF"){
   $status = "Open"
   } else {$status = "NotAFinding"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77095" $status
}

function V_77097{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -System -ErrorAction Stop
  if($processMitigation.CFG.Enable -eq "OFF"){
   $status = "Open"
   } else {$status = "NotAFinding"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77097" $status
}

function V_77101{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -System -ErrorAction Stop
  if($processMitigation.SEHOP.Enable -eq "OFF"){
   $status = "Open"
   } else {$status = "NotAFinding"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77101" $status
}

function V_77103{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -System -ErrorAction Stop
  if($processMitigation.Heap.TerminateOnError -eq "OFF"){
   $status = "Open"
   } else {$status = "NotAFinding"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77103" $status
}

function V_77189{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name Acrobat.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `   
     $processMitigation.ASLR.BottomUp -eq "ON" -and `     
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77189" $status
}

function V_77191{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name AcroRd32.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `   
     $processMitigation.ASLR.BottomUp -eq "ON" -and `     
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77191" $status
}

function V_77195{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name chrome.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77195" $status
}

function V_77201{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name EXCEL.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `        
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77201" $status
}

function V_77205{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name firefox.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `   
     $processMitigation.ASLR.BottomUp -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77205" $status
}

function V_77209{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name FLTLDR.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `        
     $processMitigation.ImageLoad.BlockRemoteImageLoads -eq "ON" -and ` 
     $processMitigation.ChildProcess.DisallowChildProcessCreation -eq "ON" -and ` 
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()} 
&updateVulnStatus "V-77209" $status
}

function V_77213{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name GROOVE.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.ImageLoad.BlockRemoteImageLoads -eq "ON" -and ` 
     $processMitigation.ChildProcess.DisallowChildProcessCreation -eq "ON" -and ` 
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()} 
&updateVulnStatus "V-77213" $status
}

function V_77217{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name iexplore.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `   
     $processMitigation.ASLR.BottomUp -eq "ON" -and `     
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77217" $status
}

function V_77221{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name INFOPATH.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `        
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77221" $status
}

function V_77223{
$status="Not_Reviewed"
$processMitigation=$null
$overallStatus=$null
$statusCheck1=$null
$statusCheck2=$null
$statusCheck3=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name java.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `             
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $statusCheck1 = "NotAFinding"
   } else {$statusCheck1 = "Open"}
  $processMitigation=Get-ProcessMitigation -Name javaw.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `             
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $statusCheck2 = "NotAFinding"
   } else {$statusCheck2 = "Open"}
  $processMitigation=Get-ProcessMitigation -Name javaws.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `             
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $statusCheck3 = "NotAFinding"
   } else {$statusCheck3 = "Open"}
  if($statusCheck1 -eq "NotAFinding" -and $statusCheck2 -eq "NotAFinding" `
     -and $statusCheck3 -eq "NotAFinding"){
     $overallStatus="NotAFinding"
   } else {$overallStatus="Open"} 
  } else {$overallStatus="Not_Applicable"}
} catch {
   $overallStatus = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77223" $overallStatus
}

function V_77227{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name lync.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `        
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77227" $status
}

function V_77231{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name MSACCESS.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `        
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77231" $status
}

function V_77233{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name MSPUB.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `        
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77233" $status
}

function V_77235{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name OneDrive.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.ImageLoad.BlockRemoteImageLoads -eq "ON" -and ` 
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77235" $status
}

function V_77239{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name OIS.EXE -ErrorAction Stop 
  if($processMitigation.DEP.Enable -eq "ON" -and `      
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77239" $status
}

function V_77243{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name OUTLOOK.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77243" $status
}

function V_77245{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name plugin-container.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `      
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77245" $status
}

function V_77247{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name POWERPNT.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77247" $status
}

function V_77249{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name PPTVIEW.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77249" $status
}

function V_77255{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name VISIO.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77255" $status
}

function V_77259{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name VPREVIEW.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77259" $status 
}

function V_77263{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name WINWORD.EXE -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `
     $processMitigation.ASLR.ForceRelocateImages -eq "ON" -and `  
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77263" $status 
}

function V_77267{
$status="Not_Reviewed"
$processMitigation=$null


try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name wmplayer.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `  
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77267" $status
}

function V_77269{
$status="Not_Reviewed"
$processMitigation=$null

try{
 if($OSReleaseID -ge 1709 -and $isClassified -eq "N"){
  $processMitigation=Get-ProcessMitigation -Name wordpad.exe -ErrorAction Stop
  if($processMitigation.DEP.Enable -eq "ON" -and `  
     $processMitigation.Payload.EnableExportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableExportAddressFilterPlus -eq "ON" -and `
     $processMitigation.Payload.EnableImportAddressFilter -eq "ON" -and `
     $processMitigation.Payload.EnableRopStackPivot -eq "ON" -and `
     $processMitigation.Payload.EnableRopCallerCheck -eq "ON" -and `
     $processMitigation.Payload.EnableRopSimExec -eq "ON"){
   $status = "NotAFinding"
   } else {$status = "Open"}
  } else {$status="Not_Applicable"}
} catch {
   $status = "Not_Reviewed"
} Finally {$error.Clear()}
&updateVulnStatus "V-77269" $status
}

function V_78129{
 &updateStigCommentsField "V-78129" `
 ("Requires Manual Verification")
}

function V_82137{
$status="Not_Reviewed"
$location="HKCU:\Software\Policies\Microsoft\OneDrive\"
$key="DisablePersonalSync"
 
 $items = get-itemproperty $location -ErrorAction SilentlyContinue | select $key
  if ( $items.$key.count -eq 1 -and $items.$key -eq 1) {
    $status = "NotAFinding"    
  } else {
    $status = "Open"
  }
 &updateVulnStatus "V-82137" $status 
}

function V_88203{
 &updateStigCommentsField "V-88203" `
 ("Requires Manual Verification")
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
Write-Output "Starting Checks Not Reviewed STIG Items:"
&runVulnerabilityChecks
cls
Write-Output "Importing XCCDF Results.  Do not close this window."
&importXCCDFResults
&saveUpdatedCkl
cls
Write-Output "Script executed successfully."
Write-Output ("The updated CKL is located here: " + (Get-Location) + "\Reports")
#####END main()#####


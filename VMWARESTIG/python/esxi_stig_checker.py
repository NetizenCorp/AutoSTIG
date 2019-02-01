import os
import subprocess

import paramiko

from stig_report import stig_report

class esxi_stig(object):

    def __init__(self):
        self.powershell = None
        self.output = None
        self.vcenter = None
        self.esxi_server = None
        self.esxi_username = None
        self.esxi_password = None
        self.vcenter_log = None

    def ssh_connect(self):
        self.p_transport = paramiko.Transport((self.esxi_server, 22))
        self.p_transport.connect(username=self.esxi_username, password=self.esxi_password)

    def ssh_command(self, command):
        nbytes = 4096
        stdout_data = []
        stderr_data = []
        session = self.p_transport.open_channel(kind='session')
        session.exec_command(command)
        while True:
            if session.recv_ready():
                stdout_data.append(session.recv(nbytes))
            if session.recv_stderr_ready():
                stderr_data.append(session.recv_stderr(nbytes))
            if session.exit_status_ready():
                break

        #print 'exit status: ', session.recv_exit_status()
        return ''.join(stdout_data)
        #print ''.join(stderr_data)
        session.close()

    def ssh_close(self):        
        self.p_transport.close()

    def esxi_connect(self):
        COMMAND_LINE = 'powershell'
        self.powershell = subprocess.Popen(COMMAND_LINE, shell=True,
                                           stdin=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdout=subprocess.PIPE)
        self.output = self.powershell.stdout.readline()

        self.powershell.stdin.write('Set-Location "C:\Program Files (x86)\VMware\Infrastructure\PowerCLI\Scripts"\r\n')
        self.powershell.stdin.write('.\Initialize-PowerCLIEnvironment.ps1\r\n')
        self.powershell.stdin.flush()
        self.powershell.stdin.write("Connect-VIServer " + self.esxi_server + " -Port 443 " +
                                    "-User " + self.esxi_username + " -Password '" + self.esxi_password + "'\r\n")
        self.powershell.stdin.flush()
        self.powershell.stdin.write("Write-Output '########'\n\r")
        self.powershell.stdin.flush()
        self.vcenter_log = open('esxi_stig_output.txt','w')

    def esxi_command(self, command):
        self.powershell.stdin.write(command)
        self.powershell.stdin.flush()

    def esxi_close(self):
        self.output = self.powershell.stdout.readline()
        out = self.powershell.communicate()[0]
        return(out)

    def esxi_ssh_shell(self, mode):
        COMMAND_LINE = 'powershell'
        self.powershell = subprocess.Popen(COMMAND_LINE, shell=True,
                                           stdin=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdout=subprocess.PIPE)
        self.output = self.powershell.stdout.readline()
        
        passed_command = 'Get-VMHost | Foreach {Start-VMHostService -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"})'
        self.esxi_command(passed_command)
        self.output = self.powershell.stdout.readline()
        out = self.powershell.communicate()[0]

    def esxi_run(self):
        print ("Start")
        self.esxi_connect()
        #s = stig_report()
       
        vuln_num = 'V-None'
        cat_num = 'None'
        passed_command = 'Get-VMHost | Foreach {Start-VMHostService -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} )}\n\r'
        self.esxi_command(passed_command)

        passed_command = 'Get-VMHost | Foreach {Start-VMHostService -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM"} )}\n\r'
        self.esxi_command(passed_command)

        vuln_num = 'V-63147'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63173'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name DCUI.Access'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63175'
        cat_num = 'CAT III'
        passed_command = ('$vmhost = Get-VMHost | Get-View;' +
                          '$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager;' +
                          '$lockdown.QueryLockdownExceptions()')
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()
    
        #1
        vuln_num = 'V-63177'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63179'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63181'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63183'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63185'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63229'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #vuln_num = 'V-63231'
        #cat_num = 'CAT II'
        #passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        #self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

       
        vuln_num = 'V-63237'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63239'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63241'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63243'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63245'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, @{N="HostProfile";E={$_ | Get-VMHostProfile}}, @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")


        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()

        vuln_num = 'V-63247'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63251'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63251'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63255'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63257'
        cat_num = 'CAT III'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.system.coredump.partition.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63257'
        cat_num = 'CAT III'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.system.coredump.network.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")


        vuln_num = 'V-63259'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63261'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostNTPServer'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()

        #3

        vuln_num = 'V-63261'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63263'
        cat_num = 'CAT I'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.software.acceptance.get()"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63275'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHostSnmp | Select *'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63277'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63279'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63281'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostFirewallException | Where {$_.Enabled -eq $true} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63283'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHostFirewallDefaultPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63283'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63287'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualSwitch | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #4

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()

        vuln_num = 'V-63287'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63289'
        cat_num = 'CAT I'
        passed_command = 'Get-VirtualSwitch | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63289'
        cat_num = 'CAT I'
        passed_command = 'Get-VirtualPortGroup | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63291'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualSwitch | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63291'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Get-SecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63293'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63295'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Select Name, VLanId'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63297'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Select Name, VLanID'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()
        #5

        vuln_num = 'V-63299'
        cat_num = 'CAT II'
        passed_command = 'Get-VirtualPortGroup | Select Name, VLanID'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63465'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63477'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63485'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63501'
        #needs to ssh into esxi

        vuln_num = 'V-63509'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #6

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()

        vuln_num = 'V-63531'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63605'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63757'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63769'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63773'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63775'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #7
        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()

        vuln_num = 'V-63777'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63779'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostNTPServer'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63779'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63823'
        cat_num = 'CAT I'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.software.acceptance.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63833'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63867'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63885'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63893'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63895'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63897'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #8
        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        
        self.esxi_connect()


        vuln_num = 'V-63901'
        cat_num = 'CAT I'
        passed_command = '$esxcli = Get-EsxCli; $esxcli.software.acceptance.get()'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63903'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63905'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63907'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-VMHostAuthentication'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63909'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        self.esxi_connect()


        #9

        vuln_num = 'V-63911'
        cat_num = 'CAT III'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63915'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63915'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        #10

        vuln_num = 'V-63921'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63923'
        cat_num = 'CAT II'
        passed_command = 'Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")


        '''
        vuln_num = 'V-73135'
        cat_num = 'CAT III'
        passed_command = 'If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){Write-Host "VSAN Enabled Cluster found"Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match "vsan"}}else{Write-Host "VSAN is not enabled, this finding is not applicable"}'
        e.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")
        '''

        
        for p in self.esxi_close().split('########'):
            if ("V-" in p and not "Get-" in p) or ("The requested operation" in p):
                #s.write_row(p.split('$$$$$$$$')[0].split('|')[0].strip(), p.split('$$$$$$$$')[0].split('|')[1].strip())
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""
        #s.close_report()

        self.esxi_ssh_shell('start')

        #self.ssh_connect()
        #self.ssh_command('grep -i "^Ciphers" /etc/ssh/sshd_config')
        #self.ssh_command('ls')
        #self.ssh_close()

        

        #2
        self.ssh_connect()
        vuln_num = 'V-63187'        
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^Banner" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        #self.ssh_close

        #self.ssh_connect()
        vuln_num = 'V-63189'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^Ciphers" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        #
        
        vuln_num = 'V-63191'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^Protocol" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63193'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^IgnoreRhosts" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63195'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')

        vuln_num = 'V-63197'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^PermitRootLogin" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63199'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63201'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')

        
        vuln_num = 'V-63203'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^MACs" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63205'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^GSSAPIAuthentication" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63207'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^KerberosAuthentication" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
                
        vuln_num = 'V-63209'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^StrictModes" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        
        vuln_num = 'V-63211'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^Compression" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63213'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^GatewayPorts" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63215'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^X11Forwarding" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63217'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^AcceptEnv" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
                
        vuln_num = 'V-63219'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^PermitTunnel" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63221'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63223'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^ClientAliveInterval" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63225'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^MaxSessions" /etc/ssh/sshd_config') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63227'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('cat /etc/ssh/keys-root/authorized_keys') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')
        
        vuln_num = 'V-63229'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('cat /etc/ssh/keys-root/authorized_keys') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')

        vuln_num = 'V-63233'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^password" /etc/pam.d/passwd | grep sufficient') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')

        vuln_num = 'V-63235'
        self.vcenter_log.write('########\n\r')
        self.vcenter_log.write(vuln_num + '\n\r' + self.ssh_command('grep -i "^password" /etc/pam.d/passwd | grep sufficient') + "\n\r")
        self.vcenter_log.write('########\n\r\n\r')

        self.ssh_close

        print ("SSH Close")


        self.esxi_connect()

        passed_command = 'Get-VMHost | Foreach {Stop-VMHostService -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} )}\n\r'
        self.esxi_command(passed_command)

        passed_command = 'Get-VMHost | Foreach {Stop-VMHostService -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM"} )}\n\r'
        self.esxi_command(passed_command)

        self.esxi_close()

        self.vcenter_log.close()
        
        print "Done"
        
      

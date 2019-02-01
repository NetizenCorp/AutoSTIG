import os
import subprocess

class esxi_vcenter():

    def __init__(self):
        self.powershell = None
        self.output = None
        self.vcenter_ip = ""
        self.vcenter_username = ""
        self.vcenter_password = ""
        self.vcenter_log = None

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
        self.powershell.stdin.write("Connect-VIServer " + self.vcenter_ip +
                                    " -Port 443 -User " + self.vcenter_username +
                                    " -Password '" + self.vcenter_password + "'\r\n")
        self.powershell.stdin.flush()
        self.powershell.stdin.write("Write-Output '########'\n\r")
        self.powershell.stdin.flush()
        self.vcenter_log = open('vcenter_stig_output.txt','w')

    def esxi_command(self, command):
        self.powershell.stdin.write(command)
        self.powershell.stdin.flush()

    def esxi_close(self):
        self.output = self.powershell.stdout.readline()
        out = self.powershell.communicate()[0]
        return(out)

    def vcenter_run(self):
        print 
        self.esxi_connect()

        print ("Start esxi")

        self.esxi_command("Write-Output '########'")

        vuln_num = 'V-63949'
        cat_num = 'CAT II'
        passed_command = 'Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63951')
        cat_num = 'CAT II'
        passed_command = 'Get-VDSwitch | select Name,@{N="NIOC Enabled";E={$_.ExtensionData.config.NetworkResourceManagementEnabled}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63953')
        cat_num = 'CAT III'
        passed_command = 'Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "esx.problem.vmsyslogd.remote.failure"} | Select Name,Enabled,@{N="EventTypeId";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63961')
        cat_num = 'CAT III'
        passed_command = '$vds = Get-VDSwitch;$vds.ExtensionData.Config.HealthCheckConfig'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63963, V-63965, V-63967')
        cat_num = ('CAT II, CAT I, CAT II')
        passed_command = 'Get-VDSwitch | Get-VDSecurityPolicy;Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63969')
        cat_num = 'CAT II'
        passed_command = 'Get-VDSwitch | select Name,@{N="NetFlowCollectorIPs";E={$_.ExtensionData.config.IpfixConfig.CollectorIpAddress}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = 'V-63971'
        cat_num = 'CAT III'
        passed_command = ('Get-VDPortgroup | Get-View | Select Name, ' + 
                       '@{N="VlanOverrideAllowed";E={$_.Config.Policy.VlanOverrideAllowed}}, ' +
                       '@{N="UplinkTeamingOverrideAllowed";E={$_.Config.Policy.UplinkTeamingOverrideAllowed}}, ' +
                       '@{N="SecurityPolicyOverrideAllowed";E={$_.Config.Policy.SecurityPolicyOverrideAllowed}}, ' + 
                       '@{N="IpfixOverrideAllowed";E={$_.Config.Policy.IpfixOverrideAllowed}}, ' +
                       '@{N="BlockOverrideAllowed";E={$_.Config.Policy.BlockOverrideAllowed}}, ' + 
                       '@{N="ShapingOverrideAllowed";E={$_.Config.Policy.ShapingOverrideAllowed}}, ' + 
                       '@{N="VendorConfigOverrideAllowed";E={$_.Config.Policy.VendorConfigOverrideAllowed}}, ' + 
                       '@{N="TrafficFilterOverrideAllowed";E={$_.Config.Policy.TrafficFilterOverrideAllowed}}, ' +
                       '@{N="PortConfigResetAtDisconnect";E={$_.Config.Policy.PortConfigResetAtDisconnect}} | Sort Name')
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63973, V-63975, V-63977')
        cat_num = ('CAT II, CAT II, CAT II')
        passed_command = 'Get-VDPortgroup | select Name, VlanConfiguration'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63979')
        cat_num = 'CAT II'
        passed_command = 'Get-AdvancedSetting -Entity ' + self.vcenter_ip + ' -Name config.nfc.useSSL'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63983')
        cat_num = 'CAT II'
        passed_command = 'Get-AdvancedSetting -Entity ' + self.vcenter_ip + ' -Name VirtualCenter.VimPasswordExpirationInDays'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63985')
        cat_num = 'CAT II'
        passed_command = 'Get-AdvancedSetting -Entity ' + self.vcenter_ip + ' -Name config.vpxd.hostPasswordLength'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-63995')
        #Need to build ssh capabilites

        vuln_num = ('V-64013')
        cat_num = 'CAT III'
        passed_command = 'Get-AdvancedSetting -Entity ' + self.vcenter_ip + ' -Name config.log.level'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-64031, V-64033, V-64035')
        cat_num = ('CAT II, CAT II, CAT II')
        passed_command = 'Get-AlarmDefinition | Where {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "vim.event.PermissionAddedEvent"} | Select Name,Enabled,@{N="EventTypeId";E={$_.ExtensionData.Info.Expression.Expression.EventTypeId}}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-64037')
        cat_num = 'CAT II'
        passed_command = 'Get-VIPermission | Sort Role | Select Role,Principal,Entity,Propagate,IsGroup | FT -Auto'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        vuln_num = ('V-73143')
        cat_num = 'CAT III'
        passed_command = 'If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){Write-Host "VSAN Enabled Cluster found"Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match "vsan"}}else{Write-Host "VSAN is not enabled, this finding is not applicable"}'
        self.esxi_command("Write-Output '########';Write-Output '" + vuln_num + " |';" + passed_command + ";Write-Output '$$$$$$$$'\n\r")

        for  p in self.esxi_close().split('########'):
            if "V-" in p and not "Get-" in p:
                self.vcenter_log.write('########\n\r')
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[0] + "\n\r")
                self.vcenter_log.write(p.split('$$$$$$$$')[0].split('|')[1] + "\n\r")
                self.vcenter_log.write('########\n\r\n\r')
                print p.split('$$$$$$$$')[0].split('|')[0]
                print p.split('$$$$$$$$')[0].split('|')[1]
                print ""

        self.vcenter_log.close()

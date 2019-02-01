import os
import subprocess

import paramiko

from stig_report import stig_report

class esxi_stig_ssh(object):

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

    def esxi_ssh_run(self):
        print ("Start")
        self.esxi_connect()
        self.esxi_ssh_shell('start')
        
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
        self.esxi_close()
        print ("SSH Close")
      
        
      

import os
import subprocess

from stig_report import stig_report

class powershell_check(object):

    def __init__(self):
        self.powershell = None
        self.output = None
        self.vcenter = None
        self.esxi_server = None
        self.esxi_username = None
        self.esxi_password = None
        self.vcenter_log = None

    def powershell_connect(self):
        COMMAND_LINE = 'powershell'
        self.powershell = subprocess.Popen(COMMAND_LINE, shell=True,
                                           stdin=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdout=subprocess.PIPE)
        self.output = self.powershell.stdout.readline()

        

        self.powershell.stdin.write('Set-Location "C:\Program Files (x86)\VMware\Infrastructure\PowerCLI\Scripts"\r\n')
        self.powershell.stdin.write('.\Initialize-PowerCLIEnvironment.ps1\r\n')
        self.powershell.stdin.flush()
        self.output = self.powershell.stdout.readline()
        out = self.powershell.communicate()[0]
        #print (out)
        if "cannot be loaded because running" in out and "scripts is disabled on this system" in out:
            print ("Cannot run script.")
            self.powershell = subprocess.Popen(COMMAND_LINE, shell=True,
                                           stdin=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdout=subprocess.PIPE)
            self.output = self.powershell.stdout.readline()
            
            passed_command = 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted\n\r'
            self.powershell_command(passed_command)
            self.output = self.powershell.stdout.readline()
            out = self.powershell.communicate()[0]
            print (out)

            
        #self.powershell.stdin.write("Connect-VIServer " + self.esxi_server + " -Port 443 " +
        #                            "-User " + self.esxi_username + " -Password '" + self.esxi_password + "'\r\n")
        #self.powershell.stdin.flush()
        #self.powershell.stdin.write("Write-Output '########'\n\r")
        #self.powershell.stdin.flush()
        #self.vcenter_log = open('esxi_stig_output.txt','w')

    def powershell_reset(self):
        COMMAND_LINE = 'powershell'
        self.powershell = subprocess.Popen(COMMAND_LINE, shell=True,
                                           stdin=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           stdout=subprocess.PIPE)
        self.output = self.powershell.stdout.readline()
        
        passed_command = 'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Restricted\n\r'
        self.powershell_command(passed_command)
        self.output = self.powershell.stdout.readline()
        out = self.powershell.communicate()[0]

    def powershell_command(self, command):
        self.powershell.stdin.write(command)
        self.powershell.stdin.flush()

    def powershell_close(self):
        self.output = self.powershell.stdout.readline()
        out = self.powershell.communicate()[0]
        return(out)

    def powershell_run(self):
        print ("Start")

        self.powershell_connect()

        

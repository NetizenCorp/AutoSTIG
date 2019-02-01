Imports Renci.SshNet
Imports System
Imports System.IO
Imports Renci.SshNet.Sftp
Imports System.Text.RegularExpressions

Imports VMware.Vim
Imports System.Collections.Specialized
Imports System.Security.Cryptography.X509Certificates
Imports System.Net.Security
Imports System.Net

Imports System.Web.Services.Protocols
'Imports VimService

Public Class Form1
    Public FarmVMs As New List(Of VirtualMachine)

    Private Sub HandleKeyEvent(ByVal sender As Object, ByVal e As Renci.SshNet.Common.AuthenticationPromptEventArgs)
        For Each prompt As Renci.SshNet.Common.AuthenticationPrompt In e.Prompts
            If (prompt.Request.IndexOf("Password:", StringComparison.InvariantCultureIgnoreCase) <> -1) Then
                prompt.Response = "free$411"
            End If

        Next
    End Sub

    Function CertificateValidationCallBack(
    ByVal sender As Object,
    ByVal certificate As X509Certificate,
    ByVal chain As X509Chain,
    ByVal sslPolicyErrors As SslPolicyErrors
) As Boolean

        Return True
    End Function


    Private Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click

        ServicePointManager.ServerCertificateValidationCallback = New RemoteCertificateValidationCallback(AddressOf CertificateValidationCallBack)
        Dim c As VimClientImpl = New VimClientImpl
        Dim SVC As ServiceContent = c.Connect("https://10.0.3.10/sdk")
        Dim US As UserSession = c.Login("root", "free$411")

        Dim filter As NameValueCollection = New NameValueCollection

        'filter.Add()

        'Dim kauth As KeyboardInteractiveAuthenticationMethod = New KeyboardInteractiveAuthenticationMethod("root")
        'Dim pauth As PasswordAuthenticationMethod = New PasswordAuthenticationMethod("root", "free$411")
        'AddHandler kauth.AuthenticationPrompt, AddressOf Me.HandleKeyEvent
        'Dim connectionInfo As ConnectionInfo = New ConnectionInfo("10.0.3.10", 22, "root", pauth, kauth)
        'Dim SshClient = New SshClient(connectionInfo)
        'SshClient.KeepAliveInterval = TimeSpan.FromSeconds(60)
        'SshClient.Connect()

        'Dim result = SshClient.RunCommand("df -h")

        'SshClient.Disconnect()

        'Debug.Print(result.Result)

    End Sub
End Class

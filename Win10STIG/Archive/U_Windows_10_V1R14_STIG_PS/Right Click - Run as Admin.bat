@echo off
PowerShell.exe -ExecutionPolicy Bypass /noexit -Command "& {Set-Location -Path %~dp0/Script}";"& {./Win10.ps1}"





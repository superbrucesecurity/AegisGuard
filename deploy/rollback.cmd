@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Rollback.ps1" %*

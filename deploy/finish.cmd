@echo off
setlocal
rem Uso: finish.cmd [INSTALLDIR] [DATADIR] [TASKPREFIX] [SHORTCUTNAME]
rem Sin argumentos usa las rutas y nombres de produccion.
set "INSTALLDIR=%~1"
if "%INSTALLDIR%"=="" set "INSTALLDIR=%ProgramW6432%\AegisGuard"
if "%INSTALLDIR%"=="" set "INSTALLDIR=%ProgramFiles%\AegisGuard"
set "DATADIR=%~2"
if "%DATADIR%"=="" set "DATADIR=%ProgramData%\AegisGuard"
set "TASKPREFIX=%~3"
if "%TASKPREFIX%"=="" set "TASKPREFIX=AegisGuard"
set "SHORTCUTNAME=%~4"
if "%SHORTCUTNAME%"=="" set "SHORTCUTNAME=Aegis Guard"

for /f %%u in ('powershell.exe -NoProfile -Command "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"') do set "USERSID=*%%u"

echo Restringiendo permisos de %DATADIR%...
icacls "%DATADIR%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "%USERSID%:(OI)(CI)F" /T >nul
if errorlevel 1 goto :fail

echo Registrando arranque automatico...
schtasks /Create /TN "%TASKPREFIX% Service" /TR "\"%INSTALLDIR%\run-service.cmd\"" /SC ONLOGON /RL HIGHEST /F >nul
if errorlevel 1 goto :fail

echo Creando accesos directos...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Create-Shortcuts.ps1" -InstallDir "%INSTALLDIR%" -ShortcutName "%SHORTCUTNAME%"
if errorlevel 1 goto :fail

echo Finalizacion completada.
exit /b 0

:fail
echo Error: no se pudo completar la configuracion. Revise los permisos y los privilegios.
exit /b 1

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\AegisGuard",
    [string]$DataDir = "$env:ProgramData\AegisGuard",
    [switch]$KeepData,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Este desinstalador debe ejecutarse desde un shell con privilegios de administrador.'
}

Write-Host 'Deteniendo tareas y procesos de Aegis Guard...'
foreach ($name in @('AegisGuard Service', 'AegisGuard Gateway')) {
    #Una tarea ya eliminada no debe abortar la desinstalación.
    & cmd.exe /c "schtasks /Delete /TN `"$name`" /F >nul 2>&1" | Out-Null
}
Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase) } |
    Stop-Process -Force -ErrorAction SilentlyContinue

$links = @(
    (Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Aegis Guard.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Aegis Guard.lnk'),
    (Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'Aegis Guard.lnk')
)
foreach ($link in $links) { Remove-Item $link -Force -ErrorAction SilentlyContinue }

if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "Eliminado: $InstallDir"
}

if ($KeepData) {
    Write-Host "Se conserva el estado en $DataDir (incluye cuarentena y claves)."
}
elseif (Test-Path $DataDir) {
    if (-not $Yes) {
        $answer = Read-Host "¿Eliminar también $DataDir (eventos, cuarentena y credenciales)? [s/N]"
        if ($answer -notmatch '^[sS]') {
            Write-Host "Se conserva el estado en $DataDir."
            return
        }
    }
    Remove-Item $DataDir -Recurse -Force
    Write-Host "Eliminado: $DataDir"
}

Write-Host 'Desinstalación completada.'

[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$DataDir,
    [string]$TaskPrefix = 'AegisGuard',
    [string]$ShortcutName = 'Aegis Guard',
    [switch]$KeepData,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Este desinstalador debe ejecutarse desde un shell con privilegios de administrador.'
}

$programFiles = $env:ProgramW6432
if ([string]::IsNullOrWhiteSpace($programFiles)) { $programFiles = $env:ProgramFiles }
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $programFiles 'AegisGuard' }
if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Join-Path $env:ProgramData 'AegisGuard' }
$separator = [IO.Path]::DirectorySeparatorChar

Write-Host 'Deteniendo tareas y procesos de Aegis Guard...'
$tasks = & schtasks /Query /FO CSV /NH 2>$null
foreach ($line in $tasks) {
    $name = ($line -split '","')[0].Trim('"')
    if ($name.StartsWith($TaskPrefix + ' ', [StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith($TaskPrefix + $separator, [StringComparison]::OrdinalIgnoreCase)) {
        & cmd.exe /c "schtasks /Delete /TN `"$name`" /F >nul 2>&1" | Out-Null
    }
}

$processes = @(Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir + $separator, [StringComparison]::OrdinalIgnoreCase) })
$processes | Stop-Process -Force -ErrorAction SilentlyContinue
foreach ($process in $processes) {
    try { $process.WaitForExit(5000) | Out-Null } catch { # ya terminó
    }
}

Write-Host 'Eliminando reglas del firewall creadas por el producto...'
& netsh advfirewall firewall delete rule name="AEGIS Guard*" 2>$null | Out-Null

Write-Host 'Eliminando accesos directos...'
$shell = New-Object -ComObject WScript.Shell
foreach ($folder in @('StartMenu', 'Desktop', 'CommonDesktopDirectory')) {
    $directory = [Environment]::GetFolderPath($folder)
    if ([string]::IsNullOrWhiteSpace($directory) -or -not (Test-Path -LiteralPath $directory)) { continue }
    foreach ($link in Get-ChildItem -LiteralPath $directory -Filter '*.lnk' -File -ErrorAction SilentlyContinue) {
        try {
            $target = $shell.CreateShortcut($link.FullName).TargetPath
            $ownShortcut = $link.Name -eq "$ShortcutName.lnk"
            $pointsHere = -not [string]::IsNullOrWhiteSpace($target) -and
                          $target.StartsWith($InstallDir + $separator, [StringComparison]::OrdinalIgnoreCase)
            if ($ownShortcut -or $pointsHere) { Remove-Item -LiteralPath $link.FullName -Force }
        } catch { /* acceso directo ilegible */ }
    }
}

if (Test-Path -LiteralPath $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "Eliminado: $InstallDir"
}

$webViewData = Join-Path $env:LOCALAPPDATA 'AegisGuard\WebView2'
if (Test-Path -LiteralPath $webViewData) {
    Remove-Item -LiteralPath $webViewData -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Eliminado: $webViewData"
}

if ($KeepData) {
    Write-Host "Se conserva el estado en $DataDir (incluye cuarentena y claves)."
}
elseif (Test-Path -LiteralPath $DataDir) {
    # Los canarios están en perfiles de usuario: hay que limpiarlos antes de
    # borrar el manifiesto que guarda sus rutas.
    $manifest = Join-Path $DataDir 'canaries.json'
    if (Test-Path -LiteralPath $manifest) {
        try {
            $canaries = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
            foreach ($property in $canaries.Hashes.PSObject.Properties) {
                $path = $property.Name
                if (-not (Test-Path -LiteralPath $path)) { continue }
                try {
                    Set-ItemProperty -LiteralPath $path -Name Attributes -Value ([IO.FileAttributes]::Normal)
                    Remove-Item -LiteralPath $path -Force
                } catch { Write-Warning "No se pudo eliminar el canario $path" }
            }
        } catch { Write-Warning 'No se pudo leer el manifiesto de canarios.' }
    }

    if (-not $Yes -and -not [Environment]::UserInteractive) {
        Write-Warning "Sesión no interactiva: se conserva el estado en $DataDir. Use -Yes para eliminarlo."
    }
    elseif (-not $Yes) {
        $answer = Read-Host "¿Eliminar también $DataDir (eventos, cuarentena y credenciales)? [s/N]"
        if ($answer -notmatch '^[sS]') {
            Write-Host "Se conserva el estado en $DataDir."
            Write-Host 'Desinstalación completada.'
            return
        }
    }
    Remove-Item -LiteralPath $DataDir -Recurse -Force
    Write-Host "Eliminado: $DataDir"
}

Write-Host 'Desinstalación completada.'

[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$DataDir,
    [string]$TaskPrefix = 'AegisGuard',
    [string]$ServiceName = 'AegisGuardSvc',
    [string]$ShortcutName = 'Aegis Guard',
    [switch]$KeepData,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Este desinstalador debe ejecutarse desde un shell con privilegios de administrador.'
}

function Assert-SafeDirectory([string]$Path, [string]$Label, [string[]]$RequiredMarkers) {
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $forbidden = @(
        $root,
        $env:SystemRoot,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:USERPROFILE
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
    if ($forbidden -contains $full.TrimEnd('\')) {
        throw "$Label no puede ser una raíz del sistema: $full"
    }
    if (Test-Path -LiteralPath $full) {
        $found = $RequiredMarkers | Where-Object { Test-Path -LiteralPath (Join-Path $full $_) }
        if (-not $found) { throw "$Label no contiene un marcador de Aegis Guard: $full" }
    }
    return $full
}

function Test-CanaryPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $false }
    $name = [IO.Path]::GetFileName($full)
    if ($name -notmatch '^\.aegis-canary-[a-z0-9_-]+\.txt$') { return $false }
    $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    $roots = @(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory),
        [Environment]::GetFolderPath([Environment+SpecialFolder]::MyDocuments),
        (Join-Path $profile 'Downloads')
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
    $separator = [IO.Path]::DirectorySeparatorChar
    $owned = @($roots | Where-Object { $full.StartsWith($_ + $separator, [StringComparison]::OrdinalIgnoreCase) })
    return ($owned.Count -gt 0)
}

$programFiles = $env:ProgramW6432
if ([string]::IsNullOrWhiteSpace($programFiles)) { $programFiles = $env:ProgramFiles }
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $programFiles 'AegisGuard' }
if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Join-Path $env:ProgramData 'AegisGuard' }
$InstallDir = Assert-SafeDirectory $InstallDir 'InstallDir' @('run-service.cmd', 'Aegis.Service\Aegis.Service.exe', 'Aegis.UI\Aegis.UI.exe')
$DataDir = Assert-SafeDirectory $DataDir 'DataDir' @('config.json', 'events.jsonl', 'threats.jsonl', 'canaries.json')
$separator = [IO.Path]::DirectorySeparatorChar

Write-Host 'Deteniendo el servicio SCM de Aegis Guard...'
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        & sc.exe stop $ServiceName 2>$null | Out-Null
        for ($i = 0; $i -lt 20; $i++) {
            $current = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if (-not $current -or $current.Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
    }
    & sc.exe delete $ServiceName 2>$null | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 500
    }
}

Write-Host 'Deteniendo tareas heredadas y procesos de Aegis Guard...'
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
        } catch { # acceso directo ilegible
        }
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
    Write-Host "Se conserva el estado en $DataDir (incluye cuarentena, eventos y configuración)."
}
elseif (Test-Path -LiteralPath $DataDir) {
    if (-not $Yes -and -not [Environment]::UserInteractive) {
        Write-Warning "Sesión no interactiva: se conserva el estado en $DataDir. Use -Yes para eliminarlo."
    }
    elseif (-not $Yes) {
        $answer = Read-Host "¿Eliminar también $DataDir (eventos, cuarentena y configuración)? [s/N]"
        if ($answer -notmatch '^[sS]') {
            Write-Host "Se conserva el estado en $DataDir."
            Write-Host 'Desinstalación completada.'
            return
        }
    }

    # Los canarios están en perfiles de usuario: solo se retirán cuando el
    # usuario haya confirmado expresamente la eliminación de todo el estado.
    $manifest = Join-Path $DataDir 'canaries.json'
    if (Test-Path -LiteralPath $manifest) {
        try {
            $canaries = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
            foreach ($property in $canaries.Hashes.PSObject.Properties) {
                $path = $property.Name
                # El manifiesto es un archivo local editable: no se permite que
                # una ruta manipulada convierta la desinstalación en un borrado
                # arbitrario. Solo se retiran señuelos conocidos del perfil.
                if (-not (Test-CanaryPath $path)) {
                    Write-Warning "Ruta de canario no reconocida, se omite: $path"
                    continue
                }
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
                try {
                    Set-ItemProperty -LiteralPath $path -Name Attributes -Value ([IO.FileAttributes]::Normal)
                    Remove-Item -LiteralPath $path -Force
                } catch { Write-Warning "No se pudo eliminar el canario $path" }
            }
        } catch { Write-Warning 'No se pudo leer el manifiesto de canarios.' }
    }

    Remove-Item -LiteralPath $DataDir -Recurse -Force
    Write-Host "Eliminado: $DataDir"
}

Write-Host 'Desinstalación completada.'

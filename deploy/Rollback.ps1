[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupDir,
    [string]$InstallDir,
    [string]$ServiceName = 'AegisGuardSvc',
    [string]$ExpectedSignerSha256,
    [switch]$AllowUntrustedTestSigner,
    [switch]$SkipVerify,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute el rollback desde un shell con privilegios de administrador.'
}

function Assert-SafeDirectory([string]$Path, [string]$Label, [string[]]$Markers) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $root = [IO.Path]::GetPathRoot($full)
    $forbidden = @(
        $root,
        $env:SystemRoot,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        $env:USERPROFILE
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd([IO.Path]::DirectorySeparatorChar) }
    if ($forbidden -contains $full) { throw "$Label no puede ser una raíz del sistema: $full" }
    if (Test-Path -LiteralPath $full) {
        $found = @($Markers | Where-Object { Test-Path -LiteralPath (Join-Path $full $_) })
        if ($found.Count -eq 0) { throw "$Label no contiene marcadores de Aegis Guard: $full" }
    }
    return $full
}

$programFiles = $env:ProgramW6432
if ([string]::IsNullOrWhiteSpace($programFiles)) { $programFiles = $env:ProgramFiles }
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $programFiles 'AegisGuard' }
$BackupDir = Assert-SafeDirectory $BackupDir 'BackupDir' @('VERSION', 'RELEASE-SIGNATURES.json', 'Aegis.Service\Aegis.Service.exe', 'Aegis.UI\Aegis.UI.exe')
$InstallDir = Assert-SafeDirectory $InstallDir 'InstallDir' @('VERSION', 'Aegis.Service\Aegis.Service.exe', 'Aegis.UI\Aegis.UI.exe')
$separator = [IO.Path]::DirectorySeparatorChar
if (-not $BackupDir.Equals($InstallDir, [StringComparison]::OrdinalIgnoreCase) -and
    $BackupDir.StartsWith($InstallDir + $separator, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BackupDir no puede estar dentro de InstallDir.'
}
if (-not $InstallDir.Equals($BackupDir, [StringComparison]::OrdinalIgnoreCase) -and
    $InstallDir.StartsWith($BackupDir + $separator, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'InstallDir no puede estar dentro de BackupDir.'
}

if (-not $SkipVerify) {
    $manifest = Join-Path $BackupDir 'RELEASE-SIGNATURES.json'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw "El backup no tiene RELEASE-SIGNATURES.json; use -SkipVerify solo si es un despliegue firmado manualmente."
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedSignerSha256)) { $ExpectedSignerSha256 = $env:AEGIS_RELEASE_SIGNER_SHA256 }
    try {
        & (Join-Path $PSScriptRoot 'Verify-Release.ps1') -TargetDir $BackupDir -ManifestPath $manifest -ExpectedSignerSha256 $ExpectedSignerSha256 -AllowUntrustedTestSigner:$AllowUntrustedTestSigner
        if (-not $?) { throw 'Verify-Release.ps1 devolvió un error.' }
    }
    catch { throw "El backup no superó la verificación; no se restauró. $($_.Exception.Message)" }
}

if (-not $Yes -and [Environment]::UserInteractive) {
    $answer = Read-Host "¿Sustituir $InstallDir por el backup $BackupDir? [s/N]"
    if ($answer -notmatch '^[sS]') { Write-Host 'Rollback cancelado.'; return }
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
$startAfter = ($null -ne $service -and $service.Status -eq 'Running')
if ($null -ne $service -and $service.Status -ne 'Stopped') {
    Write-Host "Deteniendo $ServiceName..."
    & sc.exe stop $ServiceName 2>$null | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        $current = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $current -or $current.Status -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 500
    }
}

$temp = $InstallDir + '.rollback-' + [Guid]::NewGuid().ToString('N')
$swapped = $false
try {
    if (Test-Path -LiteralPath $InstallDir) { Move-Item -LiteralPath $InstallDir -Destination $temp }
    $swapped = $true
    Move-Item -LiteralPath $BackupDir -Destination $InstallDir
    if (Test-Path -LiteralPath $temp) {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $temp) { Write-Warning "No se pudo eliminar la versión sustituida: $temp" }
    }
    Write-Host "Rollback completado: $InstallDir"
    Write-Host 'El directorio de estado (cuarentena, eventos y configuración) no se ha tocado.'
    if ($startAfter) {
        & sc.exe start $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Warning "El backup se restauró, pero $ServiceName no se pudo iniciar (código $LASTEXITCODE)." }
        else { Write-Host "Servicio $ServiceName reiniciado." }
    }
}
catch {
    if ($swapped -and (Test-Path -LiteralPath $InstallDir)) {
        Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $temp) {
        Move-Item -LiteralPath $temp -Destination $InstallDir
        Write-Warning "Versión restaurada desde $temp tras un rollback fallido."
    }
    if ($startAfter) { & sc.exe start $ServiceName 2>$null | Out-Null }
    throw
}

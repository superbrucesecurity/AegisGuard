[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\AegisGuard",
    [string]$DataDir = "$env:ProgramData\AegisGuard",
    [switch]$SelfContained
)

$ErrorActionPreference = 'Stop'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute este instalador desde un shell con privilegios de administrador.'
}

function Assert-SafeDirectory([string]$Path, [string]$Label) {
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
    return $full
}

$InstallDir = Assert-SafeDirectory $InstallDir 'InstallDir'
$DataDir = Assert-SafeDirectory $DataDir 'DataDir'
$root = Split-Path -Parent $PSScriptRoot
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

# La ACL se aplica antes de escribir cualquier archivo de estado.
& icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*$userSid:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'No se pudieron restringir los permisos del directorio de estado.' }

$ridArgs = if ($SelfContained) { @('-r', 'win-x64', '--self-contained', 'true') } else { @('--self-contained', 'false') }
$projects = @(
    @{ Project = 'src/Aegis.Service/Aegis.Service.csproj'; Target = 'Aegis.Service' },
    @{ Project = 'src/Aegis.UI/Aegis.UI.csproj'; Target = 'Aegis.UI' }
)

$stage = Join-Path ([IO.Path]::GetTempPath()) ('aegis-' + [Guid]::NewGuid().ToString('N'))
try {
    foreach ($item in $projects) {
        $out = Join-Path $stage $item.Target
        $dest = Join-Path $InstallDir $item.Target
        Write-Host "Publicando $($item.Target)..."
        & dotnet publish (Join-Path $root $item.Project) -c Release -o $out @ridArgs -v quiet
        if ($LASTEXITCODE -ne 0) { throw "Falló la publicación de $($item.Target)." }
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -Path (Join-Path $out '*') -Destination $dest -Recurse -Force
    }

    $rulesDest = Join-Path $InstallDir 'rules'
    New-Item -ItemType Directory -Force -Path $rulesDest | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $root 'rules') -File | Copy-Item -Destination $rulesDest -Force

    $serviceExe = Join-Path $InstallDir 'Aegis.Service\Aegis.Service.exe'
    $uiExe = Join-Path $InstallDir 'Aegis.UI\Aegis.UI.exe'
    $serviceCmd = "@echo off`r`nset `"AEGIS_DATA_DIR=$DataDir`"`r`nset `"AEGIS_RULES_DIR=$rulesDest`"`r`nstart `"`" /B `"$serviceExe`"`r`n"
    $uiCmd = "@echo off`r`nset `"AEGIS_DATA_DIR=$DataDir`"`r`nstart `"`" /B `"$uiExe`"`r`n"
    [IO.File]::WriteAllText((Join-Path $InstallDir 'run-service.cmd'), $serviceCmd)
    [IO.File]::WriteAllText((Join-Path $InstallDir 'run-ui.cmd'), $uiCmd)

    Write-Host ''
    Write-Host 'Archivos instalados; el producto no usa credenciales ni servicios externos.'
    Write-Host "  Producto: $InstallDir"
    Write-Host "  Estado:   $DataDir"
    Write-Host "  Reglas:   $rulesDest"
    Write-Host ''
    Write-Host 'Para reforzar permisos, registrar el arranque automático y crear accesos directos, ejecute como administrador:'
    Write-Host "  $(Join-Path $PSScriptRoot 'finish.cmd') `"$InstallDir`" `"$DataDir`""
    Write-Host ''
    Write-Host 'Para iniciar ahora:'
    Write-Host "  Start-Process '$(Join-Path $InstallDir 'run-service.cmd')'"
    Write-Host "  Start-Process '$(Join-Path $InstallDir 'run-ui.cmd')'"
}
finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}

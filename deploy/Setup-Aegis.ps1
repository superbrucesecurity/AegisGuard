[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\AegisGuard",
    [string]$DataDir = "$env:ProgramData\AegisGuard",
    [string]$LiquidApiKey = $env:LIQUID_API_KEY,
    [ValidateSet('d1.2-ultra', 'd1.2')]
    [string]$Model = 'd1.2-ultra',
    [switch]$SelfContained
)

$ErrorActionPreference = 'Stop'

$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecute este instalador desde un shell con privilegios de administrador.'
}

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($LiquidApiKey)) {
    throw 'Proporcione -LiquidApiKey o defina LIQUID_API_KEY antes de llamar al instalador.'
}
$LiquidApiKey = $LiquidApiKey.Trim()
if ($LiquidApiKey.Length -lt 20) { throw 'La clave de Liquid AI no tiene el formato esperado.' }
if (-not $LiquidApiKey.StartsWith('liquid', [StringComparison]::OrdinalIgnoreCase)) {
    $LiquidApiKey = 'liquid' + $LiquidApiKey
}

$bytes = [byte[]]::new(32)
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$gatewayKey = [Convert]::ToBase64String($bytes)

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$ridArgs = if ($SelfContained) { @('-r', 'win-x64', '--self-contained', 'true') } else { @('--self-contained', 'false') }
$projects = @(
    @{ Project = 'src/Aegis.Service/Aegis.Service.csproj'; Target = 'Aegis.Service' },
    @{ Project = 'src/Aegis.CloudGateway/Aegis.CloudGateway.csproj'; Target = 'Aegis.Gateway' },
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
        # Copy-Item sobre un destino inexistente lo crea como hoja y falla al copiar
        # subdirectorios (arm64, x64, runtimes). El destino debe ser carpeta primero.
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item (Join-Path $out '*') $dest -Recurse -Force
    }

    $rulesDest = Join-Path $InstallDir 'rules'
    New-Item -ItemType Directory -Force -Path $rulesDest | Out-Null
    Copy-Item (Join-Path $root 'rules\*') $rulesDest -Recurse -Force

    $envPath = Join-Path $DataDir 'gateway.env'
    $lines = @(
        "LIQUID_API_KEY=$LiquidApiKey",
        "AEGIS_GATEWAY_KEY=$gatewayKey",
        'AEGIS_GATEWAY_URL=http://127.0.0.1:8790',
        "LIQUID_MODEL=$Model"
    )
    [IO.File]::WriteAllLines($envPath, $lines)

    $serviceExe = Join-Path $InstallDir 'Aegis.Service\Aegis.Service.exe'
    $gatewayExe = Join-Path $InstallDir 'Aegis.Gateway\Aegis.CloudGateway.exe'
    $uiExe = Join-Path $InstallDir 'Aegis.UI\Aegis.UI.exe'
    [IO.File]::WriteAllText((Join-Path $InstallDir 'run-service.cmd'), "@echo off`r`nstart `"`" /B `"$serviceExe`"`r`n")
    [IO.File]::WriteAllText((Join-Path $InstallDir 'run-gateway.cmd'), "@echo off`r`nstart `"`" /B `"$gatewayExe`"`r`n")

    Write-Host ''
    Write-Host 'Archivos instalados y configuración escrita.'
    Write-Host "  Producto: $InstallDir"
    Write-Host "  Estado:   $DataDir"
    Write-Host "  Modelo:   $Model"
    Write-Host ''
    Write-Host 'Para reforzar permisos, registrar el arranque automático y crear accesos directos, ejecute como administrador:'
    Write-Host "  $(Join-Path $PSScriptRoot 'finish.cmd')"
    Write-Host ''
    Write-Host 'Para iniciar ahora:'
    Write-Host "  Start-Process '$(Join-Path $InstallDir 'run-gateway.cmd')'"
    Write-Host "  Start-Process '$(Join-Path $InstallDir 'run-service.cmd')'"
    Write-Host "  Start-Process '$uiExe'"
}
finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}

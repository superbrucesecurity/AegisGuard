[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [Parameter(Mandatory = $true)]
    [string]$DataDir,
    [string]$ServiceName = 'AegisGuardSvc',
    [string]$DisplayName = 'Aegis Guard Service',
    [string]$TaskPrefix = 'AegisGuard',
    [string]$IntelPackageDir,
    [string]$IntelKeyHash
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Registre el servicio desde un shell con privilegios de administrador.'
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
        throw "$Label no puede ser una raiz del sistema: $full"
    }
    return $full
}

function Invoke-ScStrict([string[]]$ScArgs) {
    & sc.exe @ScArgs | Out-Null
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw "sc.exe $($ScArgs[0]) fallo con codigo $code"
    }
}

if ($ServiceName -notmatch '^[A-Za-z0-9_.-]{1,80}$') {
    throw "Nombre de servicio no valido: $ServiceName"
}
$hasPackageDir = -not [string]::IsNullOrWhiteSpace($IntelPackageDir)
$hasKeyHash = -not [string]::IsNullOrWhiteSpace($IntelKeyHash)
if ($hasPackageDir -ne $hasKeyHash) {
    throw 'Debe indicar juntos IntelPackageDir e IntelKeyHash, o ninguno.'
}
if ($hasKeyHash -and $IntelKeyHash -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'IntelKeyHash debe ser un SHA-256 de 64 caracteres hexadecimales.'
}
if ($hasPackageDir -and -not (Test-Path -LiteralPath $IntelPackageDir -PathType Container)) {
    throw "No se encontro el paquete de inteligencia: $IntelPackageDir"
}

$InstallDir = Assert-SafeDirectory $InstallDir 'InstallDir'
$DataDir = Assert-SafeDirectory $DataDir 'DataDir'
$rulesDir = Join-Path $InstallDir 'rules'
$serviceExe = Join-Path $InstallDir 'Aegis.Service\Aegis.Service.exe'
if (-not (Test-Path -LiteralPath $serviceExe -PathType Leaf)) {
    throw "No se encontro $serviceExe"
}
if (-not (Test-Path -LiteralPath $rulesDir -PathType Container)) {
    throw "No se encontro el directorio de reglas $rulesDir"
}

Write-Host "Registrando $ServiceName como servicio SCM..."

# Migracion desde v2.0.0: la tarea ONLOGON ya no es necesaria.
if (-not [string]::IsNullOrWhiteSpace($TaskPrefix)) {
    $tasks = & schtasks /Query /FO CSV /NH 2>$null
    foreach ($line in $tasks) {
        $name = ($line -split '","')[0].Trim('"')
        if ($name -eq "$TaskPrefix Service") {
            & schtasks /Delete /TN $name /F 2>$null | Out-Null
        }
    }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') {
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

$binPath = '"' + $serviceExe + '"'
Invoke-ScStrict @('create', $ServiceName, 'binPath=', $binPath, 'start=', 'auto',
                  'DisplayName=', $DisplayName, 'obj=', 'LocalSystem')
Invoke-ScStrict @('description', $ServiceName, 'Aegis Guard: defensa local con servicio automatico sin sesion.')
Invoke-ScStrict @('failure', $ServiceName, 'reset=', '86400', 'actions=',
                  'restart/5000/restart/10000/restart/30000')
Invoke-ScStrict @('failureflag', $ServiceName, '1')

# Las variables de entorno del servicio se leen del registro del SCM: asi el
# binPath es directo y el proceso responde a los controles de stop/shutdown.
$uiSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$serviceEnv = @(
    "AEGIS_DATA_DIR=$DataDir",
    "AEGIS_RULES_DIR=$rulesDir",
    "AEGIS_SERVICE_NAME=$ServiceName",
    'AEGIS_SERVICE_MANAGED=1',
    "AEGIS_UI_USER_SID=$uiSid"
)
if ($hasPackageDir) {
    $serviceEnv += "AEGIS_INTEL_PACKAGE_DIR=$IntelPackageDir"
    $serviceEnv += "AEGIS_INTEL_KEY_SHA256=$IntelKeyHash"
}
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
    -Name Environment -PropertyType MultiString -Value $serviceEnv -Force | Out-Null

& sc.exe start $ServiceName 2>$null | Out-Null
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056) {
    throw "No se pudo iniciar $ServiceName (codigo $LASTEXITCODE)."
}

$service = $null
for ($i = 0; $i -lt 40; $i++) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') { break }
    Start-Sleep -Milliseconds 500
}
if (-not $service -or $service.Status -ne 'Running') {
    throw "El servicio $ServiceName no alcanzo el estado Running."
}

$tokenPath = Join-Path $DataDir 'ui-token'
for ($i = 0; $i -lt 20 -and -not (Test-Path -LiteralPath $tokenPath); $i++) {
    Start-Sleep -Milliseconds 500
}
if (-not (Test-Path -LiteralPath $tokenPath)) {
    throw "El servicio no genero $tokenPath."
}

$token = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
$headers = @{ Authorization = "Bearer $token" }
$health = $null
for ($i = 0; $i -lt 20; $i++) {
    try {
        $health = Invoke-RestMethod 'http://127.0.0.1:8787/api/health' -Headers $headers -TimeoutSec 2
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}
if (-not $health) {
    throw 'El servicio responde pero la API local con token no devolvio /api/health.'
}

[pscustomobject]@{
    ServiceName = $ServiceName
    StartType = 'auto'
    Status = $service.Status
    ProcessId = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").ProcessId
    EventSource = $ServiceName
    ApiVersion = $health.version
} | Format-List

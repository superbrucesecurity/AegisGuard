[CmdletBinding()]
param(
    [int]$Seconds = 30,
    [string]$DataDir,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Join-Path ([IO.Path]::GetTempPath()) 'aegis-benchmark-data' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'artifacts\benchmark.json' }

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null

$startedByUs = $false
$serviceProcess = $null
try { Invoke-WebRequest 'http://127.0.0.1:8787/healthz' -UseBasicParsing -TimeoutSec 2 | Out-Null; $alreadyRunning = $true }
catch { $alreadyRunning = $false }

if ($alreadyRunning) {
    $connection = Get-NetTCPConnection -LocalPort 8787 -State Listen -ErrorAction Stop | Select-Object -First 1
    $processId = $connection.OwningProcess
    Write-Host " midiendo el servicio ya en ejecución (PID $processId)."
}
else {
    $dll = Join-Path $root 'src\Aegis.Service\bin\Debug\net10.0\Aegis.Service.dll'
    if (-not (Test-Path -LiteralPath $dll)) { throw "No se encontró $dll. Ejecute dotnet build antes de medir." }
    $oldData = $env:AEGIS_DATA_DIR
    $oldRules = $env:AEGIS_RULES_DIR
    $env:AEGIS_DATA_DIR = $DataDir
    $env:AEGIS_RULES_DIR = Join-Path $root 'rules'
    try { $serviceProcess = Start-Process -FilePath 'dotnet' -ArgumentList @($dll) -PassThru -WindowStyle Hidden }
    finally {
        $env:AEGIS_DATA_DIR = $oldData
        $env:AEGIS_RULES_DIR = $oldRules
    }
    $processId = $serviceProcess.Id
    $startedByUs = $true
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try { Invoke-WebRequest 'http://127.0.0.1:8787/healthz' -UseBasicParsing -TimeoutSec 1 | Out-Null; $ready = $true; break }
        catch { } # todavía arrancando
    }
    if (-not $ready) { throw 'El servicio no respondió a /healthz; revise los permisos y el puerto 8787.' }
    Write-Host " servicio iniciado para la medición (PID $processId)."
}

$status = $null
$samples = @()
try {
    $previous = Get-Process -Id $processId -ErrorAction Stop
    $previousTime = Get-Date
    $previousCpu = $previous.TotalProcessorTime.TotalMilliseconds

    for ($i = 0; $i -lt $Seconds; $i++) {
        Start-Sleep -Seconds 1
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($null -eq $process) { throw 'El servicio se detuvo durante la medición.' }
        $now = Get-Date
        $cpu = $process.TotalProcessorTime.TotalMilliseconds
        $elapsed = ($now - $previousTime).TotalMilliseconds
        $cpuPercent = [Math]::Max(0, ($cpu - $previousCpu) / [Math]::Max(1, $elapsed) * 100 / [Environment]::ProcessorCount)
        $samples += [pscustomobject]@{
            cpuPercent     = [Math]::Round($cpuPercent, 3)
            workingSetBytes = $process.WorkingSet64
        }
        $previousTime = $now
        $previousCpu = $cpu
    }

    # El estado se lee antes de detener el proceso para conservar protectionState.
    $tokenPath = Join-Path $DataDir 'ui-token'
    if (Test-Path -LiteralPath $tokenPath) {
        try {
            $token = (Get-Content -LiteralPath $tokenPath -Raw).Trim()
            $headers = @{ Authorization = "Bearer $token" }
            $status = Invoke-RestMethod 'http://127.0.0.1:8787/api/status' -Headers $headers -TimeoutSec 3
        }
        catch { $status = $null }
    }
}
finally {
    if ($startedByUs -and $null -ne $serviceProcess) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
}

$cpuValues = @($samples | ForEach-Object { [double]$_.cpuPercent })
$ramValues = @($samples | ForEach-Object { [long]$_.workingSetBytes })

$result = [ordered]@{
    measuredAtUtc     = [DateTimeOffset]::UtcNow.ToString('o')
    durationSeconds   = $Seconds
    processorCount    = [Environment]::ProcessorCount
    cpuAveragePercent = [Math]::Round((($cpuValues | Measure-Object -Average).Average), 3)
    cpuMaxPercent     = [Math]::Round((($cpuValues | Measure-Object -Maximum).Maximum), 3)
    ramAverageBytes   = [long]($ramValues | Measure-Object -Average).Average
    ramMaxBytes       = [long]($ramValues | Measure-Object -Maximum).Maximum
    samples           = $samples.Count
    serviceStatus     = $status
    notes             = 'Sin scan activo. ETW/WFP pueden estar degradados sin privilegios de administrador.'
}
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host ''
Write-Host "CPU medio: $([Math]::Round($result.cpuAveragePercent,2)) % | máximo: $([Math]::Round($result.cpuMaxPercent,2)) %"
Write-Host "RAM media: $([Math]::Round($result.ramAverageBytes / 1MB,1)) MB | máxima: $([Math]::Round($result.ramMaxBytes / 1MB,1)) MB"
Write-Host "Resultado guardado en $OutputPath"

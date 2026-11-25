[CmdletBinding()]
param(
    [int]$Seconds = 30,
    [string]$DataDir,
    [string]$OutputPath,
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$LaunchUi,
    [switch]$SkipLoad,
    [int]$ScanCount = 20,
    [int]$LargeFileBytes = 262144
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Join-Path ([IO.Path]::GetTempPath()) 'aegis-benchmark-data' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'artifacts\benchmark.json' }
if ($Seconds -lt 1) { throw 'Seconds debe ser al menos 1.' }
if ($ScanCount -lt 1) { throw 'ScanCount debe ser al menos 1.' }
if ($LargeFileBytes -lt 1 -or $LargeFileBytes -gt 16MB) { throw 'LargeFileBytes debe estar entre 1 y 16777216.' }

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputPath) | Out-Null

function Get-ProcessTreeIds {
    param([hashtable]$Children, [int]$RootId)
    $result = New-Object 'System.Collections.Generic.List[int]'
    $queue = New-Object 'System.Collections.Generic.Queue[int]'
    $queue.Enqueue($RootId)
    while ($queue.Count -gt 0) {
        $id = $queue.Dequeue()
        $result.Add($id) | Out-Null
        if ($Children.ContainsKey($id)) {
            foreach ($child in $Children[$id]) { $queue.Enqueue([int]$child.ProcessId) }
        }
    }
    return $result
}

function Get-ProcessSnapshot {
    param([int]$RootId)
    $all = @(Get-CimInstance Win32_Process)
    $children = @{}
    foreach ($p in $all) {
        $parent = [int]$p.ParentProcessId
        if (-not $children.ContainsKey($parent)) { $children[$parent] = @() }
        $children[$parent] += $p
    }
    $serviceIds = Get-ProcessTreeIds -Children $children -RootId $RootId
    $serviceRead = [long]0
    $serviceWrite = [long]0
    foreach ($p in $all) {
        if ($serviceIds -contains [int]$p.ProcessId) {
            $serviceRead += [long]$p.ReadTransferCount
            $serviceWrite += [long]$p.WriteTransferCount
        }
    }
    $uiIds = New-Object 'System.Collections.Generic.List[int]'
    foreach ($p in $all) {
        if ($p.Name -eq 'Aegis.UI.exe') {
            $uiIds.AddRange([int[]](Get-ProcessTreeIds -Children $children -RootId ([int]$p.ProcessId)))
        }
    }
    $uiWorkingSet = [long]0
    $webviewWorkingSet = [long]0
    $webviewCount = 0
    foreach ($p in $all) {
        if ($uiIds -contains [int]$p.ProcessId) {
            $uiWorkingSet += [long]$p.WorkingSetSize
            if ($p.Name -eq 'msedgewebview2.exe') {
                $webviewCount++
                $webviewWorkingSet += [long]$p.WorkingSetSize
            }
        }
    }
    return [pscustomobject]@{
        ServiceProcessCount    = $serviceIds.Count
        ServiceReadBytes       = $serviceRead
        ServiceWriteBytes      = $serviceWrite
        UiProcessCount         = $uiIds.Count
        UiWorkingSetBytes      = $uiWorkingSet
        WebviewCount           = $webviewCount
        WebviewWorkingSetBytes = $webviewWorkingSet
    }
}

function Get-Percentile {
    param([double[]]$Values, [double]$Quantile)
    if ($Values.Count -eq 0) { return $null }
    $index = [int][Math]::Floor($Quantile * ($Values.Count - 1))
    return [Math]::Round($Values[$index], 2)
}

$startedByUs = $false
$serviceProcess = $null
$startupMs = $null
$startupMeasured = $false
$buildConfiguration = 'unknown-reused-service'
$processId = $null
try { Invoke-WebRequest 'http://127.0.0.1:8787/healthz' -UseBasicParsing -TimeoutSec 2 | Out-Null; $alreadyRunning = $true }
catch { $alreadyRunning = $false }

if ($alreadyRunning) {
    $connection = Get-NetTCPConnection -LocalPort 8787 -State Listen -ErrorAction Stop | Select-Object -First 1
    $processId = [int]$connection.OwningProcess
    Write-Host " midiendo el servicio ya en ejecución (PID $processId); no se conoce su configuración de compilación."
}
else {
    $dll = Join-Path $root ("src\Aegis.Service\bin\$Configuration\net10.0\Aegis.Service.dll")
    if (-not (Test-Path -LiteralPath $dll)) { throw "No se encontró $dll. Ejecute dotnet build -c $Configuration antes de medir." }
    $oldData = $env:AEGIS_DATA_DIR
    $oldRules = $env:AEGIS_RULES_DIR
    $env:AEGIS_DATA_DIR = $DataDir
    $env:AEGIS_RULES_DIR = Join-Path $root 'rules'
    $startupWatch = [Diagnostics.Stopwatch]::StartNew()
    try { $serviceProcess = Start-Process -FilePath 'dotnet' -ArgumentList @($dll) -PassThru -WindowStyle Hidden }
    finally {
        $env:AEGIS_DATA_DIR = $oldData
        $env:AEGIS_RULES_DIR = $oldRules
    }
    $processId = [int]$serviceProcess.Id
    $startedByUs = $true
    $buildConfiguration = $Configuration
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        try { Invoke-WebRequest 'http://127.0.0.1:8787/healthz' -UseBasicParsing -TimeoutSec 1 | Out-Null; $ready = $true; break }
        catch { } # todavía arrancando
    }
    $startupWatch.Stop()
    if (-not $ready) { throw 'El servicio no respondió a /healthz; revise los permisos y el puerto 8787.' }
    $startupMs = [Math]::Round($startupWatch.Elapsed.TotalMilliseconds, 1)
    $startupMeasured = $true
    Write-Host " servicio $Configuration iniciado para la medición (PID $processId, arranque $startupMs ms)."
}

$uiProcess = $null
$webviewBefore = @()
if ($LaunchUi) {
    $webviewBefore = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'msedgewebview2.exe' } | ForEach-Object { [int]$_.ProcessId })
    $uiExe = Join-Path $root ("src\Aegis.UI\bin\$Configuration\net10.0-windows\Aegis.UI.exe")
    if (-not (Test-Path -LiteralPath $uiExe)) { throw "No se encontró $uiExe. Ejecute dotnet build -c $Configuration antes de medir." }
    $oldUiData = $env:AEGIS_DATA_DIR
    $env:AEGIS_DATA_DIR = $DataDir
    try { $uiProcess = Start-Process -FilePath $uiExe -PassThru }
    finally { $env:AEGIS_DATA_DIR = $oldUiData }
    Write-Host " UI iniciada para medir WebView2 (PID $($uiProcess.Id))."
}

$status = $null
$samples = @()
$loadDir = $null
try {
    $previous = Get-Process -Id $processId -ErrorAction Stop
    $previousTime = Get-Date
    $previousCpu = $previous.TotalProcessorTime.TotalMilliseconds
    $previousSnapshot = Get-ProcessSnapshot -RootId $processId
    $previousRead = $previousSnapshot.ServiceReadBytes
    $previousWrite = $previousSnapshot.ServiceWriteBytes

    for ($i = 0; $i -lt $Seconds; $i++) {
        Start-Sleep -Seconds 1
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($null -eq $process) { throw 'El servicio se detuvo durante la medición.' }
        $now = Get-Date
        $cpu = $process.TotalProcessorTime.TotalMilliseconds
        $elapsed = ($now - $previousTime).TotalMilliseconds
        $cpuPercent = [Math]::Max(0, ($cpu - $previousCpu) / [Math]::Max(1, $elapsed) * 100 / [Environment]::ProcessorCount)
        $snapshot = Get-ProcessSnapshot -RootId $processId
        $readBytes = [Math]::Max(0, $snapshot.ServiceReadBytes - $previousRead)
        $writeBytes = [Math]::Max(0, $snapshot.ServiceWriteBytes - $previousWrite)
        $samples += [pscustomobject]@{
            second                 = $i + 1
            cpuPercent             = [Math]::Round($cpuPercent, 3)
            workingSetBytes        = $process.WorkingSet64
            privateBytes           = $process.PrivateMemorySize64
            diskReadBytes          = $readBytes
            diskWriteBytes         = $writeBytes
            processCount           = $snapshot.ServiceProcessCount
            webviewCount           = $snapshot.WebviewCount
            webviewWorkingSetBytes = $snapshot.WebviewWorkingSetBytes
        }
        $previousTime = $now
        $previousCpu = $cpu
        $previousRead = $snapshot.ServiceReadBytes
        $previousWrite = $snapshot.ServiceWriteBytes
    }

    # El estado se lee antes de la fase de carga para conservar la línea base.
    # Ya no existe token local: las lecturas HTTP son anónimas y solo en loopback.
    try { $status = Invoke-RestMethod 'http://127.0.0.1:8787/api/status' -TimeoutSec 5 }
    catch { $status = $null }

    $load = $null
    if (-not $SkipLoad) {
            $loadDir = Join-Path $DataDir ('benchmark-load-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Force -Path $loadDir | Out-Null
            # Señales para el analizador de scripts, construidas en tiempo de
            # ejecución: el fichero .ps1 del benchmark no contiene código ejecutable.
            $encodedToken = [string]::Concat('-enc', 'odedcommand')
            $expressionToken = [string]::Concat('ie', 'x(')
            $executionToken = [string]::Concat('wscript', '.shell')
            $scriptBody = @(
                '# Synthetic benchmark input; no executable payload.'
                ('# señales: ' + $encodedToken + ' ' + $expressionToken + ' ' + $executionToken)
                ('$a = ' + "'a'" + ' + ' + "'b'")
            ) -join "`r`n"
            $paths = @()
            for ($i = 0; $i -lt $ScanCount; $i++) {
                $path = Join-Path $loadDir ('synthetic-{0:d3}.ps1' -f $i)
                [IO.File]::WriteAllText($path, $scriptBody)
                $paths += $path
            }
            $largePath = Join-Path $loadDir 'large.bin'
            [IO.File]::WriteAllBytes($largePath, (New-Object byte[] $LargeFileBytes))
            $paths += $largePath

            $before = $null
            $after = $null
            try { $before = Invoke-RestMethod 'http://127.0.0.1:8787/api/status' -TimeoutSec 5 } catch { }
            $latencies = @()
            $verdicts = @{}
            $errors = @()
            $largeLatencyMs = $null
            $overall = [Diagnostics.Stopwatch]::StartNew()
            foreach ($path in $paths) {
                $watch = [Diagnostics.Stopwatch]::StartNew()
                try {
                    $body = @{ path = $path } | ConvertTo-Json -Compress
                    $response = Invoke-WebRequest -Uri 'http://127.0.0.1:8787/api/scan' -Method Post -Body $body `
                        -ContentType 'application/json' -UseBasicParsing -TimeoutSec 60
                    $watch.Stop()
                    $latency = [Math]::Round($watch.Elapsed.TotalMilliseconds, 2)
                    $latencies += [double]$latency
                    if ($path -eq $largePath) { $largeLatencyMs = $latency }
                    $parsed = $response.Content | ConvertFrom-Json
                    $verdict = [string]$parsed.decision.verdict
                    if (-not $verdicts.ContainsKey($verdict)) { $verdicts[$verdict] = 0 }
                    $verdicts[$verdict]++
                }
                catch {
                    $watch.Stop()
                    $message = $_.Exception.Message
                    if ($message.Length -gt 200) { $message = $message.Substring(0, 200) }
                    $errors += $message
                }
            }
            $overall.Stop()
            try { $after = Invoke-RestMethod 'http://127.0.0.1:8787/api/status' -TimeoutSec 5 } catch { }
            $sorted = @($latencies | Sort-Object)
            $delta = if ($null -ne $before -and $null -ne $after) {
                [ordered]@{
                    eventsTotal     = [long]$after.eventsTotal - [long]$before.eventsTotal
                    threatsTotal    = [long]$after.threatsTotal - [long]$before.threatsTotal
                    droppedEvents   = [long]$after.droppedEvents - [long]$before.droppedEvents
                    coalescedEvents = [long]$after.coalescedEvents - [long]$before.coalescedEvents
                }
            } else { $null }
            $load = [ordered]@{
                performed           = $true
                requests            = $paths.Count
                failures            = $errors.Count
                durationSeconds     = [Math]::Round($overall.Elapsed.TotalSeconds, 3)
                throughputPerSecond = [Math]::Round($paths.Count / [Math]::Max(0.001, $overall.Elapsed.TotalSeconds), 3)
                latencyAverageMs    = if ($sorted.Count -gt 0) { [Math]::Round((($sorted | Measure-Object -Average).Average), 2) } else { $null }
                latencyP95Ms        = Get-Percentile -Values ([double[]]$sorted) -Quantile 0.95
                latencyMaxMs        = if ($sorted.Count -gt 0) { [double]$sorted[$sorted.Count - 1] } else { $null }
                largeFileBytes      = $LargeFileBytes
                largeFileLatencyMs  = $largeLatencyMs
                verdicts            = $verdicts
                deltas              = $delta
                endQueue            = if ($null -ne $after) {
                    [ordered]@{
                        criticalDepth = $after.criticalQueueDepth
                        normalDepth   = $after.normalQueueDepth
                        oldestSeconds = $after.oldestQueuedSeconds
                    }
                } else { $null }
                errors              = $errors
            }
    }
}
finally {
    if ($null -ne $loadDir -and (Test-Path -LiteralPath $loadDir)) {
        Remove-Item -LiteralPath $loadDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $uiProcess) {
        Stop-Process -Id $uiProcess.Id -Force -ErrorAction SilentlyContinue
        $webviewAfter = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'msedgewebview2.exe' })
        foreach ($p in $webviewAfter) {
            $id = [int]$p.ProcessId
            $ownsIt = ($webviewBefore -notcontains $id) -and
                (($p.CommandLine -like '*Aegis.UI.exe*') -or ($p.CommandLine -like '*AegisGuard*WebView2*'))
            if ($ownsIt) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
        }
    }
    if ($startedByUs -and $null -ne $serviceProcess) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
}

$cpuValues = @($samples | ForEach-Object { [double]$_.cpuPercent })
$ramValues = @($samples | ForEach-Object { [long]$_.workingSetBytes })
$readValues = @($samples | ForEach-Object { [long]$_.diskReadBytes })
$writeValues = @($samples | ForEach-Object { [long]$_.diskWriteBytes })
$webviewValues = @($samples | ForEach-Object { [long]$_.webviewWorkingSetBytes })

$result = [ordered]@{
    measuredAtUtc        = [DateTimeOffset]::UtcNow.ToString('o')
    durationSeconds      = $Seconds
    processorCount       = [Environment]::ProcessorCount
    buildConfiguration   = $buildConfiguration
    startupMeasured      = $startupMeasured
    startupMs            = $startupMs
    cpuAveragePercent    = [Math]::Round((($cpuValues | Measure-Object -Average).Average), 3)
    cpuMaxPercent        = [Math]::Round((($cpuValues | Measure-Object -Maximum).Maximum), 3)
    ramAverageBytes      = [long]($ramValues | Measure-Object -Average).Average
    ramMaxBytes          = [long]($ramValues | Measure-Object -Maximum).Maximum
    diskReadBytes        = [long](($readValues | Measure-Object -Sum).Sum)
    diskWriteBytes       = [long](($writeValues | Measure-Object -Sum).Sum)
    serviceProcessesMax  = [int](($samples | ForEach-Object { [int]$_.processCount } | Measure-Object -Maximum).Maximum)
    uiLaunched           = [bool]($null -ne $uiProcess)
    webviewObserved      = [bool](@($samples | Where-Object { [int]$_.webviewCount -gt 0 }).Count -gt 0)
    webviewProcessesMax  = [int](($samples | ForEach-Object { [int]$_.webviewCount } | Measure-Object -Maximum).Maximum)
    webviewRamMaxBytes   = [long](($webviewValues | Measure-Object -Maximum).Maximum)
    samples              = $samples.Count
    serviceStatus        = $status
    load                 = $load
    notes                = 'Fase de reposo sin escaneos manuales. La fase de carga usa ficheros sintéticos no ejecutables creados y borrados por el script. WebView2 solo se mide si Aegis.UI.exe está en ejecución y no se suma a la RAM del servicio. ETW/WFP pueden estar degradados sin privilegios de administrador.'
}
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8

Write-Host ''
Write-Host "CPU medio: $([Math]::Round($result.cpuAveragePercent,2)) % | máximo: $([Math]::Round($result.cpuMaxPercent,2)) %"
Write-Host "RAM media: $([Math]::Round($result.ramAverageBytes / 1MB,1)) MB | máxima: $([Math]::Round($result.ramMaxBytes / 1MB,1)) MB"
Write-Host "E/S en reposo: $([Math]::Round($result.diskReadBytes / 1KB,1)) KB leídos | $([Math]::Round($result.diskWriteBytes / 1KB,1)) KB escritos"
if ($null -ne $load -and $load.performed) {
    Write-Host "Carga: $($load.requests) peticiones | latencia media $($load.latencyAverageMs) ms | p95 $($load.latencyP95Ms) ms | $($load.throughputPerSecond) scan/s"
}
Write-Host "Resultado guardado en $OutputPath"

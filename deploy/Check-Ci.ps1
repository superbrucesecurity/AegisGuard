[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

# 1. Todos los scripts de despliegue deben parsear antes de ejecutarse en CI.
$scripts = @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File | Sort-Object Name)
Assert-True ($scripts.Count -gt 0) 'No se encontraron scripts en deploy/.'
foreach ($script in $scripts) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $details = ($errors | ForEach-Object { $_.Message }) -join '; '
        throw "Error de sintaxis en $($script.Name): $details"
    }
}
Write-Host "Sintaxis correcta en $($scripts.Count) scripts de despliegue."

# Los scripts que el paquete debe arrastrar están fijados en Setup-Aegis.ps1.
# Se comprueban uno a uno, incluidos los .cmd, para que quitar uno de la copia
# no pase desapercibido.
$packagedScripts = @(
    'Setup-Aegis.ps1', 'install.cmd', 'finish.cmd', 'uninstall.cmd', 'uninstall.ps1',
    'Register-Service.ps1', 'Create-Shortcuts.ps1',
    'Verify-Release.ps1', 'Verify-Archive.ps1', 'Rollback.ps1', 'rollback.cmd'
)

# 2. El SBOM y los avisos committed deben coincidir con el grafo de dependencias real.
$generated = Join-Path ([IO.Path]::GetTempPath()) ('aegis-ci-docs-' + [Guid]::NewGuid().ToString('N'))
$generatedLicenses = Join-Path $generated 'licenses'
New-Item -ItemType Directory -Force -Path $generatedLicenses | Out-Null
try {
    & (Join-Path $PSScriptRoot 'Generate-Sbom.ps1') `
        -OutputPath (Join-Path $generated 'SBOM.spdx.json') `
        -NoticePath (Join-Path $generated 'THIRD-PARTY-NOTICES.md') `
        -LicenseDir $generatedLicenses
    if (-not $?) { throw 'Generate-Sbom.ps1 no terminó correctamente.' }

    function Get-NoticeRows([string]$Path) {
        @(Get-Content -LiteralPath $Path |
            Where-Object { $_ -match '^\| ' -and $_ -notmatch '^\| ---' -and $_ -notmatch '^\| Paquete \|' } |
            ForEach-Object { $_.Trim() } | Sort-Object)
    }

    $currentRows = Get-NoticeRows (Join-Path $generated 'THIRD-PARTY-NOTICES.md')
    $committedRows = Get-NoticeRows (Join-Path $root 'THIRD-PARTY-NOTICES.md')
    $rowDiff = @(Compare-Object $committedRows $currentRows)
    if ($rowDiff.Count -gt 0) {
        $rowDiff | ForEach-Object { Write-Host "$($_.SideIndicator) $($_.InputObject)" }
        throw 'THIRD-PARTY-NOTICES.md no coincide con las dependencias resueltas.'
    }

    function Get-SbomPackages($Sbom) {
        @($Sbom.packages | ForEach-Object { "$($_.name)|$($_.versionInfo)|$($_.licenseDeclared)" } | Sort-Object)
    }
    $currentSbom = Get-Content -LiteralPath (Join-Path $generated 'SBOM.spdx.json') -Raw | ConvertFrom-Json
    $committedSbom = Get-Content -LiteralPath (Join-Path $root 'SBOM.spdx.json') -Raw | ConvertFrom-Json
    Assert-True ($currentSbom.spdxVersion -eq 'SPDX-2.3') 'El SBOM generado no es SPDX 2.3.'
    $sbomDiff = @(Compare-Object (Get-SbomPackages $committedSbom) (Get-SbomPackages $currentSbom))
    if ($sbomDiff.Count -gt 0) {
        $sbomDiff | ForEach-Object { Write-Host "$($_.SideIndicator) $($_.InputObject)" }
        throw 'SBOM.spdx.json no coincide con las dependencias resueltas.'
    }
    # Los textos de licencia versionados deben ser los que resuelve NuGet. Se
    # comparan como texto normalizado porque Git puede cambiar CRLF en checkout.
    $licenseFiles = @(Get-ChildItem -LiteralPath $generatedLicenses -File -ErrorAction SilentlyContinue)
    foreach ($license in $licenseFiles) {
        $committed = Join-Path $root ('licenses\' + $license.Name)
        Assert-True (Test-Path -LiteralPath $committed -PathType Leaf) "Falta licenses\$($license.Name) en el repositorio."
        $expectedText = [IO.File]::ReadAllText($license.FullName).Replace("`r`n", "`n").Trim()
        $actualText = [IO.File]::ReadAllText($committed).Replace("`r`n", "`n").Trim()
        Assert-True ($actualText -eq $expectedText) "El texto licenses\$($license.Name) no coincide con la caché NuGet."
    }
    Assert-True ($licenseFiles.Count -gt 0) 'Generate-Sbom.ps1 no resolvió ningún texto de licencia.'
    Write-Host "SBOM y avisos coherentes: $($currentSbom.packages.Count) paquetes, $($currentRows.Count) filas de aviso, $($licenseFiles.Count) textos de licencia."
}
finally {
    Remove-Item -LiteralPath $generated -Recurse -Force -ErrorAction SilentlyContinue
}

# 3. La etapa de publicación se construye de verdad y debe contener todo lo que
#    el paquete firmado necesita. No se crea ningún manifiesto ni se firma nada.
$work = Join-Path ([IO.Path]::GetTempPath()) ('aegis-ci-stage-' + [Guid]::NewGuid().ToString('N'))
$stage = Join-Path $work 'stage'
$installDir = Join-Path $work 'Program Files\AegisGuard'
$dataDir = Join-Path $work 'ProgramData\AegisGuard'
try {
    & (Join-Path $PSScriptRoot 'Setup-Aegis.ps1') `
        -StageOnly `
        -InstallDir $installDir `
        -DataDir $dataDir `
        -StageDir $stage
    if (-not $?) { throw 'Setup-Aegis.ps1 -StageOnly no terminó correctamente.' }
    Assert-True (Test-Path -LiteralPath $stage -PathType Container) 'No se generó el directorio de etapa.'

    $props = Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw
    Assert-True ($props -match '<Version>([^<]+)</Version>') 'Falta <Version> en Directory.Build.props.'
    $version = $Matches[1].Trim()
    $stageVersion = (Get-Content -LiteralPath (Join-Path $stage 'VERSION') -Raw).Trim()
    Assert-True ($stageVersion -eq $version) "VERSION de la etapa ($stageVersion) no coincide con $version."

    $required = @(
        'LICENSE', 'EULA-EVALUATION.md', 'SBOM.spdx.json', 'THIRD-PARTY-NOTICES.md',
        'run-service.cmd', 'run-ui.cmd', 'rules',
        'Aegis.Service\Aegis.Service.exe', 'Aegis.UI\Aegis.UI.exe',
        'Aegis.Service\wwwroot\app.js', 'licenses\Microsoft.Web.WebView2-1.0.3650.58.txt'
    )
    foreach ($relative in $required) {
        Assert-True (Test-Path -LiteralPath (Join-Path $stage $relative)) "Falta $relative en la etapa."
    }
    foreach ($scriptName in $packagedScripts) {
        $relative = 'deploy\' + $scriptName
        Assert-True (Test-Path -LiteralPath (Join-Path $stage $relative)) "Falta $relative en la etapa."
    }

    # Los scripts incluidos en el ZIP deben ser byte a byte los del repositorio.
    foreach ($scriptName in $packagedScripts) {
        $destination = Join-Path $stage ('deploy\' + $scriptName)
        $sourceHash = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $scriptName) -Algorithm SHA256).Hash
        $stageHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        Assert-True ($sourceHash -eq $stageHash) "El script $scriptName copiado a la etapa no coincide con el original."
    }

    $legacyFiles = @(Get-ChildItem -LiteralPath $stage -Recurse -File -Force |
        Where-Object { $_.Name -eq 'ui-token' -or $_.Name -like 'ui-token.invalid-*' })
    Assert-True ($legacyFiles.Count -eq 0) 'La etapa contiene un archivo ui-token residual.'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $stage 'RELEASE-SIGNATURES.json'))) `
        'La etapa sin firmar no debe contener RELEASE-SIGNATURES.json.'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $stage 'RELEASE-SIGNATURES.ps1'))) `
        'La etapa sin firmar no debe contener RELEASE-SIGNATURES.ps1.'

    $app = Get-Content -LiteralPath (Join-Path $stage 'Aegis.Service\wwwroot\app.js') -Raw
    Assert-True ($app -match 'privilegedCall') 'La SPA publicada no enruta operaciones por IPC privilegiado.'
    Assert-True ($app -notmatch 'AEGIS_TOKEN') 'La SPA publicada contiene AEGIS_TOKEN.'
    Assert-True ($app -notmatch 'fetch\(') 'La SPA publicada todavía pide datos por HTTP.'
    $program = Get-Content -LiteralPath (Join-Path $stage 'Aegis.Service\Program.cs') -ErrorAction SilentlyContinue -Raw
    if (-not $program) {
        $program = Get-Content -LiteralPath (Join-Path $root 'src\Aegis.Service\Program.cs') -Raw
    }
    Assert-True ($program -notmatch 'Map(Get|Post|Put|Delete)\("/api/') `
        'El servicio publica rutas /api; los datos deben ir por la tubería local.'
    $ignore = Get-Content -LiteralPath (Join-Path $root '.gitignore') -Raw
    Assert-True ($ignore -match '\*-signing-key\.json') `
        '.gitignore no cubre la clave privada de firma del paquete de inteligencia.'
    Assert-True ($ignore -match 'dev-key\.json') `
        '.gitignore no cubre dev-key.json usado por las pruebas del paquete.'
    $operations = @(
        'Health', 'Status', 'Events', 'Threats', 'QuarantineList', 'FirewallRules', 'FirewallStats',
        'FirewallLearned', 'SettingsGet', 'ScanPath', 'SelftestEicar', 'FirewallAddRule',
        'FirewallRemoveRule', 'QuarantineRestore', 'QuarantinePurge', 'PolicyChange')
    foreach ($operation in $operations) {
        Assert-True ($app -match ("op: '" + $operation + "'")) "La SPA no enlaza la operación IPC $operation."
    }
    $index = Get-Content -LiteralPath (Join-Path $stage 'Aegis.Service\wwwroot\index.html') -Raw
    Assert-True ($app -match 'renderScanReport') 'La SPA no renderiza el informe del analizador.'
    Assert-True ($index -match 'id="scanReport"') 'La etapa no incluye el panel del informe del analizador.'
    Assert-True ($program -match 'new CorrelationEngine\(\)') `
        'El servicio no registra el correlacionador en el flujo automático.'
    $correlation = Get-Content -LiteralPath (Join-Path $root 'src\Aegis.Core\CorrelationEngine.cs') -Raw
    Assert-True ($correlation -match 'MaxFiredKeys') `
        'El correlacionador no acota el conjunto de reglas ya disparadas.'
    Assert-True ($correlation -match 'CORR-SUSPICIOUS-PROCESS-PERSISTENCE') `
        'Falta la correlacion proceso a persistencia con PID observado.'

    Write-Host "Etapa verificada: $version, $($required.Count) rutas obligatorias, sin token ni manifiesto de firma."

    # 4. El análisis manual por IPC debe usar el motor real sin persistir ni
    #    remediar. El servicio publicado se comprueba de verdad: HTTP sólo sirve
    #    estáticos y /healthz, y los datos van por la tubería con identidad real.
    #    Se elige un puerto libre: un runner puede tener otro proceso en el 8787.
    $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $portProbe.Start()
    $smokePort = $portProbe.LocalEndpoint.Port
    $portProbe.Stop()
    $baseUrl = "http://127.0.0.1:$smokePort"

    $smokeData = Join-Path $work 'smoke-data'
    New-Item -ItemType Directory -Force -Path $smokeData | Out-Null

    # ETW y los watchers registrarían la actividad del propio runner durante la
    # ventana de la prueba, que no es causada por el análisis aislado. La
    # verificación desactiva esos sensores (AEGIS_MONITOR_DISABLED) y da al
    # servicio un TEMP vacío, defensa en profundidad si el indicador se retira.
    $isolatedTemp = Join-Path $work 'service-temp'
    New-Item -ItemType Directory -Force -Path $isolatedTemp | Out-Null

    $envNames = @(
        'AEGIS_DATA_DIR', 'AEGIS_RULES_DIR', 'AEGIS_UI_USER_SID', 'AEGIS_HTTP_PORT',
        'AEGIS_SCAN_ALLOWED_ROOTS', 'AEGIS_MONITOR_DISABLED', 'TMP', 'TEMP')
    $previousEnv = @{}
    foreach ($name in $envNames) { $previousEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
    $process = $null
    $stdoutPath = Join-Path $work 'service.stdout.log'
    $stderrPath = Join-Path $work 'service.stderr.log'
    try {
        [Environment]::SetEnvironmentVariable('AEGIS_DATA_DIR', $smokeData)
        [Environment]::SetEnvironmentVariable('AEGIS_RULES_DIR', (Join-Path $stage 'rules'))
        $authorizedSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        [Environment]::SetEnvironmentVariable('AEGIS_UI_USER_SID', $authorizedSid)
        [Environment]::SetEnvironmentVariable('AEGIS_HTTP_PORT', [string]$smokePort)
        [Environment]::SetEnvironmentVariable('AEGIS_MONITOR_DISABLED', '1')
        [Environment]::SetEnvironmentVariable('TMP', $isolatedTemp)
        [Environment]::SetEnvironmentVariable('TEMP', $isolatedTemp)

        [Environment]::SetEnvironmentVariable('AEGIS_SCAN_ALLOWED_ROOTS', $isolatedTemp)

        $serviceExe = Join-Path $stage 'Aegis.Service\Aegis.Service.exe'
        $process = Start-Process -FilePath $serviceExe -WorkingDirectory (Join-Path $stage 'Aegis.Service') `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $health = $null
        for ($attempt = 0; $attempt -lt 80; $attempt++) {
            try {
                $health = Invoke-RestMethod -UseBasicParsing "$baseUrl/healthz" -TimeoutSec 2
                break
            }
            catch {
                if ($process.HasExited) { break }
                Start-Sleep -Milliseconds 500
            }
        }
        if ($null -eq $health) {
            foreach ($log in @($stdoutPath, $stderrPath)) {
                if (Test-Path -LiteralPath $log) {
                    Write-Host "--- $log ---"
                    Get-Content -LiteralPath $log -Tail 40
                }
            }
            throw "El servicio publicado no respondió $baseUrl/healthz en el puerto aislado $smokePort."
        }
        Assert-True ("$health" -eq 'ok') "/healthz devolvió '$health'; esperaba 'ok'."

        # El nombre del pipe se deriva del SID exactamente igual que en C#.
        $sidBytes = [Text.Encoding]::UTF8.GetBytes($authorizedSid)
        $sha = [Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha.ComputeHash($sidBytes)
        $pipeHash = -join ($hashBytes[0..7] | ForEach-Object { $_.ToString('x2') })
        $pipeName = "aegisguard-$pipeHash-privileged"
        $sha.Dispose()

        function Invoke-Ipc([string]$Operation, [hashtable]$Payload = @{}) {
            $request = @{ operation = $Operation; payload = $Payload } | ConvertTo-Json -Depth 12 -Compress
            $client = [IO.Pipes.NamedPipeClientStream]::new(
                '.', $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
            try {
                $client.Connect(10000)
                $bytes = [Text.Encoding]::UTF8.GetBytes($request + "`n")
                $client.Write($bytes, 0, $bytes.Length)
                $client.Flush()
                $reader = [IO.StreamReader]::new($client, [Text.Encoding]::UTF8, $false, 4096, $true)
                $line = $reader.ReadLine()
                if (-not $line) { throw "El canal $pipeName no devolvió respuesta para $Operation." }
                $response = $line | ConvertFrom-Json
                if (-not $response.ok) { throw "IPC $Operation rechazada: $($response.error)" }
                return $response.result
            }
            finally { $client.Dispose() }
        }

        $ipcHealth = Invoke-Ipc 'Health'
        Assert-True ($ipcHealth.version -eq $version) `
            "IPC Health informó $($ipcHealth.version); esperaba $version de Directory.Build.props."

        $beforeStatus = Invoke-Ipc 'Status'
        Assert-True ($beforeStatus.monitorActive -eq $false) 'La verificación aislada no desactivó los sensores.'
        Assert-True ($beforeStatus.etwActive -eq $false) 'La verificación aislada no desactivó ETW.'
        Assert-True ($beforeStatus.protectionState -eq 'degraded') `
            'La verificación aislada no informa de protectionState=degraded.'
        $beforeEvents = @(Invoke-Ipc 'Events' @{ limit = 1000 })
        $beforeThreats = @(Invoke-Ipc 'Threats' @{ limit = 1000 })
        $beforeQuarantine = @(Invoke-Ipc 'QuarantineList')
        $beforeRules = (Invoke-Ipc 'FirewallStats').active

        $sample = Join-Path $isolatedTemp 'scan-sample.txt'
        [IO.File]::WriteAllText($sample, 'texto inocuo para comprobar que ScanPath no persiste ni remedia.')
        $scan = Invoke-Ipc 'ScanPath' @{ path = $sample }
        Assert-True ($null -ne $scan.decision) 'ScanPath no devolvió una decisión real.'
        Assert-True ($scan.report.schemaVersion -eq '1.0') 'ScanPath no devolvió el informe del analizador.'
        Assert-True (@($scan.report.analyzers).Count -eq 6) 'El informe no declara los seis analizadores.'

        # Un proceso no privilegiado no debe poder usar el motor para leer el
        # directorio de estado del servicio, aunque conozca la ruta.
        $denied = $false
        try {
            [void](Invoke-Ipc 'ScanPath' @{ path = (Join-Path $smokeData 'config.json') })
        }
        catch { $denied = ($_ | Out-String) -match 'estado' }
        Assert-True $denied 'ScanPath aceptó una ruta dentro del directorio de estado.'

        $afterStatus = Invoke-Ipc 'Status'
        $afterEvents = @(Invoke-Ipc 'Events' @{ limit = 1000 })
        $afterThreats = @(Invoke-Ipc 'Threats' @{ limit = 1000 })
        $afterQuarantine = @(Invoke-Ipc 'QuarantineList')
        $afterRules = (Invoke-Ipc 'FirewallStats').active

        Assert-True ($afterStatus.eventsTotal -eq $beforeStatus.eventsTotal) 'ScanPath incrementó eventsTotal.'
        Assert-True ($afterStatus.threatsTotal -eq $beforeStatus.threatsTotal) 'ScanPath incrementó threatsTotal.'
        Assert-True ($afterStatus.blockedTotal -eq $beforeStatus.blockedTotal) 'ScanPath incrementó blockedTotal.'
        Assert-True ($afterStatus.quarantinedTotal -eq $beforeStatus.quarantinedTotal) 'ScanPath incrementó quarantinedTotal.'
        Assert-True ($afterEvents.Count -eq $beforeEvents.Count) 'ScanPath añadió observaciones al historial.'
        Assert-True ($afterThreats.Count -eq $beforeThreats.Count) 'ScanPath añadió amenazas al historial.'
        Assert-True ($afterQuarantine.Count -eq $beforeQuarantine.Count) 'ScanPath cambió la cuarentena.'
        Assert-True ($afterRules -eq $beforeRules) 'ScanPath cambió las reglas de firewall.'
        foreach ($name in @('events.jsonl', 'threats.jsonl', 'reputation.json')) {
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $smokeData $name))) `
                "ScanPath creó $name; la petición no debe persistir estado."
        }
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $smokeData 'ui-token'))) 'Apareció ui-token durante la prueba.'

        # HTTP no debe responder operaciones de datos: ni mutaciones ni lecturas.
        foreach ($ruta in @('/', '/api/status', '/api/scan')) {
            $status = 0
            try { [void](Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($baseUrl + $ruta) -TimeoutSec 5) }
            catch { $status = [int]$_.Exception.Response.StatusCode }
            Assert-True ($status -eq 405) "POST $ruta devolvió $status; esperaba 405."
        }
        $fallback = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/api/status" -TimeoutSec 5
        Assert-True ($fallback.Headers['Content-Type'] -match 'text/html') `
            'GET /api/status devolvió datos en lugar del contenido estático.'

        Write-Host "IPC ScanPath evaluó $sample sin persistir, remediar ni crear credenciales; HTTP sólo sirve estáticos."
    }
    finally {
        if ($process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
        foreach ($name in $envNames) {
            [Environment]::SetEnvironmentVariable($name, $previousEnv[$name])
        }
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Comprobaciones de CI correctas.'

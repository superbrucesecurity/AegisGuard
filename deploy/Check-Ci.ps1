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

# 2. El SBOM y los avisos committed deben coincidir con el grafo de dependencias real.
$generated = Join-Path ([IO.Path]::GetTempPath()) ('aegis-ci-docs-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $generated | Out-Null
try {
    & (Join-Path $PSScriptRoot 'Generate-Sbom.ps1') `
        -OutputPath (Join-Path $generated 'SBOM.spdx.json') `
        -NoticePath (Join-Path $generated 'THIRD-PARTY-NOTICES.md')
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
    Write-Host "SBOM y avisos coherentes: $($currentSbom.packages.Count) paquetes, $($currentRows.Count) filas de aviso."
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
        'Aegis.Service\wwwroot\app.js',
        'deploy\Setup-Aegis.ps1', 'deploy\finish.cmd', 'deploy\uninstall.cmd',
        'deploy\Verify-Release.ps1', 'deploy\Verify-Archive.ps1', 'deploy\Rollback.ps1'
    )
    foreach ($relative in $required) {
        Assert-True (Test-Path -LiteralPath (Join-Path $stage $relative)) "Falta $relative en la etapa."
    }

    # Los scripts incluidos en el ZIP deben ser byte a byte los del repositorio.
    foreach ($script in $scripts) {
        $destination = Join-Path $stage ('deploy\' + $script.Name)
        if (-not (Test-Path -LiteralPath $destination -PathType Leaf)) { continue }
        $sourceHash = (Get-FileHash -LiteralPath $script.FullName -Algorithm SHA256).Hash
        $stageHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
        Assert-True ($sourceHash -eq $stageHash) "El script $($script.Name) copiado a la etapa no coincide con el original."
    }

    $legacyFiles = @(Get-ChildItem -LiteralPath $stage -Recurse -File -Force |
        Where-Object { $_.Name -eq 'ui-token' -or $_.Name -like 'ui-token.invalid-*' })
    Assert-True ($legacyFiles.Count -eq 0) 'La etapa contiene un archivo ui-token residual.'
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $stage 'RELEASE-SIGNATURES.json'))) `
        'La etapa sin firmar no debe contener RELEASE-SIGNATURES.json.'

    $app = Get-Content -LiteralPath (Join-Path $stage 'Aegis.Service\wwwroot\app.js') -Raw
    Assert-True ($app -match 'privilegedCall') 'La SPA publicada no enruta operaciones por IPC privilegiado.'
    Assert-True ($app -notmatch 'AEGIS_TOKEN') 'La SPA publicada contiene AEGIS_TOKEN.'

    Write-Host "Etapa verificada: $version, $($required.Count) rutas obligatorias, sin token ni manifiesto de firma."

    # 4. El análisis manual por HTTP debe usar el motor real sin persistir ni
    #    remediar. Se comprueba contra el servicio publicado, no contra el
    #    código fuente, para cubrir también el contenido de la etapa. Se elige
    #    un puerto libre: un runner puede tener otro proceso en el 8787.
    $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $portProbe.Start()
    $smokePort = $portProbe.LocalEndpoint.Port
    $portProbe.Stop()
    $baseUrl = "http://127.0.0.1:$smokePort"

    $smokeData = Join-Path $work 'smoke-data'
    New-Item -ItemType Directory -Force -Path $smokeData | Out-Null

    # El monitor vigila también TEMP (AegisProfilePaths.UserDirectories). Si el
    # servicio compartiera el TEMP del verificador, la creación de la etapa y
    # de la muestra generaría eventos propios y los contadores dejarían de ser
    # una prueba de que POST /api/scan no persiste. Se le da un TEMP vacío.
    $isolatedTemp = Join-Path $work 'service-temp'
    New-Item -ItemType Directory -Force -Path $isolatedTemp | Out-Null

    $envNames = @('AEGIS_DATA_DIR', 'AEGIS_RULES_DIR', 'AEGIS_UI_USER_SID', 'AEGIS_HTTP_PORT', 'TMP', 'TEMP')
    $previousEnv = @{}
    foreach ($name in $envNames) { $previousEnv[$name] = [Environment]::GetEnvironmentVariable($name) }
    $process = $null
    $stdoutPath = Join-Path $work 'service.stdout.log'
    $stderrPath = Join-Path $work 'service.stderr.log'
    try {
        [Environment]::SetEnvironmentVariable('AEGIS_DATA_DIR', $smokeData)
        [Environment]::SetEnvironmentVariable('AEGIS_RULES_DIR', (Join-Path $stage 'rules'))
        [Environment]::SetEnvironmentVariable('AEGIS_UI_USER_SID',
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        [Environment]::SetEnvironmentVariable('AEGIS_HTTP_PORT', [string]$smokePort)
        [Environment]::SetEnvironmentVariable('TMP', $isolatedTemp)
        [Environment]::SetEnvironmentVariable('TEMP', $isolatedTemp)

        $serviceExe = Join-Path $stage 'Aegis.Service\Aegis.Service.exe'
        $process = Start-Process -FilePath $serviceExe -WorkingDirectory (Join-Path $stage 'Aegis.Service') `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $health = $null
        for ($attempt = 0; $attempt -lt 80; $attempt++) {
            try {
                $health = Invoke-RestMethod -UseBasicParsing "$baseUrl/api/health" -TimeoutSec 2
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
            throw "El servicio publicado no respondió $baseUrl/api/health en el puerto aislado $smokePort."
        }

        function Get-Api([string]$Path) {
            Invoke-RestMethod -UseBasicParsing ($baseUrl + $Path) -TimeoutSec 5
        }

        $beforeStatus = Get-Api '/api/status'
        $beforeEvents = @(Get-Api '/api/events')
        $beforeThreats = @(Get-Api '/api/threats')
        $beforeQuarantine = @(Get-Api '/api/quarantine')
        $beforeRules = (Get-Api '/api/firewall/stats').active

        $sample = Join-Path $smokeData 'scan-sample.txt'
        [IO.File]::WriteAllText($sample, 'texto inocuo para comprobar que POST /api/scan no persiste ni remedia.')
        $body = @{ path = $sample } | ConvertTo-Json -Compress
        $scan = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "$baseUrl/api/scan" `
            -Body $body -ContentType 'application/json' -TimeoutSec 10
        Assert-True ($null -ne $scan.decision) 'POST /api/scan no devolvió una decisión real.'

        $afterStatus = Get-Api '/api/status'
        $afterEvents = @(Get-Api '/api/events')
        $afterThreats = @(Get-Api '/api/threats')
        $afterQuarantine = @(Get-Api '/api/quarantine')
        $afterRules = (Get-Api '/api/firewall/stats').active

        Assert-True ($afterStatus.eventsTotal -eq $beforeStatus.eventsTotal) 'POST /api/scan incrementó eventsTotal.'
        Assert-True ($afterStatus.threatsTotal -eq $beforeStatus.threatsTotal) 'POST /api/scan incrementó threatsTotal.'
        Assert-True ($afterStatus.blockedTotal -eq $beforeStatus.blockedTotal) 'POST /api/scan incrementó blockedTotal.'
        Assert-True ($afterStatus.quarantinedTotal -eq $beforeStatus.quarantinedTotal) 'POST /api/scan incrementó quarantinedTotal.'
        Assert-True ($afterEvents.Count -eq $beforeEvents.Count) 'POST /api/scan añadió observaciones al historial.'
        Assert-True ($afterThreats.Count -eq $beforeThreats.Count) 'POST /api/scan añadió amenazas al historial.'
        Assert-True ($afterQuarantine.Count -eq $beforeQuarantine.Count) 'POST /api/scan cambió la cuarentena.'
        Assert-True ($afterRules -eq $beforeRules) 'POST /api/scan cambió las reglas de firewall.'
        foreach ($name in @('events.jsonl', 'threats.jsonl', 'reputation.json')) {
            Assert-True (-not (Test-Path -LiteralPath (Join-Path $smokeData $name))) `
                "POST /api/scan creó $name; la petición no debe persistir estado."
        }
        Assert-True (-not (Test-Path -LiteralPath (Join-Path $smokeData 'ui-token'))) 'Apareció ui-token durante la prueba.'
        Write-Host "POST /api/scan evaluó el fichero en $baseUrl sin persistir, remediar ni crear credenciales."
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

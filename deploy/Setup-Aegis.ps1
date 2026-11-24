[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\AegisGuard",
    [string]$DataDir = "$env:ProgramData\AegisGuard",
    [switch]$SelfContained,
    [switch]$StageOnly,
    [string]$StageDir,
    [string]$PackageDir,
    [string]$BackupDir,
    [string]$ExpectedSignerSha256,
    [switch]$AllowUnsigned,
    [switch]$AllowUntrustedTestSigner
)

$ErrorActionPreference = 'Stop'

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
if ($StageOnly -and $PackageDir) { throw 'StageOnly y PackageDir son mutuamente excluyentes.' }
if ($StageDir -and $PackageDir) { throw 'StageDir y PackageDir son mutuamente excluyentes.' }
if ($StageDir) { $StageDir = Assert-SafeDirectory $StageDir 'StageDir' }
if ($PackageDir) { $PackageDir = Assert-SafeDirectory $PackageDir 'PackageDir' }
if ($BackupDir) { $BackupDir = Assert-SafeDirectory $BackupDir 'BackupDir' }
if ([string]::IsNullOrWhiteSpace($ExpectedSignerSha256)) { $ExpectedSignerSha256 = $env:AEGIS_RELEASE_SIGNER_SHA256 }
if (-not [string]::IsNullOrWhiteSpace($ExpectedSignerSha256) -and $ExpectedSignerSha256 -notmatch '^[0-9a-fA-F]{64}$') {
    throw 'ExpectedSignerSha256 debe ser un SHA-256 de 64 caracteres hexadecimales.'
}
foreach ($pair in @(@($InstallDir, 'InstallDir'), @($DataDir, 'DataDir'))) {
    foreach ($candidate in @(@($PackageDir, 'PackageDir'), @($StageDir, 'StageDir'), @($BackupDir, 'BackupDir'))) {
        if ([string]::IsNullOrWhiteSpace($candidate[0])) { continue }
        if ($candidate[0].Equals($pair[0], [StringComparison]::OrdinalIgnoreCase) -or
            $candidate[0].StartsWith($pair[0] + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$($candidate[1]) no puede estar dentro de $($pair[1])."
        }
    }
}
if (-not $AllowUnsigned -and -not $PackageDir) {
    Write-Warning 'Sin -PackageDir la publicación se verifica solo si existe un manifiesto firmado en la etapa; use -StageOnly y Sign-Release.ps1 para producirlo.'
}
$root = Split-Path -Parent $PSScriptRoot
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$manifestName = 'RELEASE-SIGNATURES.json'

function Set-RestrictedAcl([string]$Path, [string]$Label) {
    $dirAce = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*${userSid}:(OI)(CI)F")
    $fileAce = @("*S-1-5-18:F", "*S-1-5-32-544:F", "*${userSid}:F")
    & icacls $Path /inheritance:r /grant:r @dirAce | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudieron restringir los permisos de $Label." }
    if (@(Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue).Count -gt 0) {
        & icacls (Join-Path $Path '*') /inheritance:r /grant:r @fileAce /T | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "No se pudieron restringir los permisos de los archivos de $Label." }
    }
}

$stage = $null
$backup = $null
$retainedBackup = $null
$replaced = $false
$ownedStage = $false
try {
    if ($PackageDir) {
        if (-not (Test-Path -LiteralPath $PackageDir -PathType Container)) { throw "No se encontró el paquete: $PackageDir" }
        $stage = $PackageDir
    }
    elseif ($StageDir) {
        if (Test-Path -LiteralPath $StageDir) { throw "StageDir ya existe; elija una ruta nueva: $StageDir" }
        $stage = $StageDir
        New-Item -ItemType Directory -Force -Path $stage | Out-Null
        $ownedStage = $true
    }
    else {
        $stage = Join-Path ([IO.Path]::GetTempPath()) ('aegis-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $stage | Out-Null
        $ownedStage = $true
    }

    if (-not $PackageDir) {
        $ridArgs = if ($SelfContained) { @('-r', 'win-x64', '--self-contained', 'true') } else { @('--self-contained', 'false') }
        $projects = @(
            @{ Project = 'src/Aegis.Service/Aegis.Service.csproj'; Target = 'Aegis.Service' },
            @{ Project = 'src/Aegis.UI/Aegis.UI.csproj'; Target = 'Aegis.UI' }
        )
        foreach ($item in $projects) {
            $out = Join-Path $stage $item.Target
            Write-Host "Publicando $($item.Target)..."
            & dotnet publish (Join-Path $root $item.Project) -c Release -o $out @ridArgs -v quiet
            if ($LASTEXITCODE -ne 0) { throw "Falló la publicación de $($item.Target)." }
            $exeName = if ($item.Target -eq 'Aegis.Service') { 'Aegis.Service.exe' } else { 'Aegis.UI.exe' }
            if (-not (Test-Path -LiteralPath (Join-Path $out $exeName))) {
                throw "La publicación de $($item.Target) no generó $exeName."
            }
        }

        $rulesDest = Join-Path $stage 'rules'
        New-Item -ItemType Directory -Force -Path $rulesDest | Out-Null
        Get-ChildItem -LiteralPath (Join-Path $root 'rules') -File | Copy-Item -Destination $rulesDest -Force

        $props = Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw
        if ($props -notmatch '<Version>([^<]+)</Version>') { throw 'No se encontró <Version> en Directory.Build.props.' }
        $version = $Matches[1].Trim()
        [IO.File]::WriteAllText((Join-Path $stage 'VERSION'), $version + "`r`n")
        foreach ($document in @('LICENSE', 'SBOM.spdx.json', 'THIRD-PARTY-NOTICES.md')) {
            $source = Join-Path $root $document
            if (Test-Path -LiteralPath $source -PathType Leaf) { Copy-Item -LiteralPath $source -Destination (Join-Path $stage $document) -Force }
        }
        $licensesSource = Join-Path $root 'licenses'
        if (Test-Path -LiteralPath $licensesSource -PathType Container) {
            $licensesDest = Join-Path $stage 'licenses'
            New-Item -ItemType Directory -Force -Path $licensesDest | Out-Null
            Copy-Item -Path (Join-Path $licensesSource '*') -Destination $licensesDest -Recurse -Force
        }

        # Las rutas son las definitivas para que la etapa firmada y el producto
        # instalado sean byte a byte idénticos.
        $finalRules = Join-Path $InstallDir 'rules'
        $serviceExe = Join-Path $InstallDir 'Aegis.Service\Aegis.Service.exe'
        $uiExe = Join-Path $InstallDir 'Aegis.UI\Aegis.UI.exe'
        $serviceCmd = "@echo off`r`nset `"AEGIS_DATA_DIR=$DataDir`"`r`nset `"AEGIS_RULES_DIR=$finalRules`"`r`nstart `"`" /B `"$serviceExe`"`r`n"
        $uiCmd = "@echo off`r`nset `"AEGIS_DATA_DIR=$DataDir`"`r`nstart `"`" /B `"$uiExe`"`r`n"
        [IO.File]::WriteAllText((Join-Path $stage 'run-service.cmd'), $serviceCmd)
        [IO.File]::WriteAllText((Join-Path $stage 'run-ui.cmd'), $uiCmd)
    }

    if ($StageOnly) {
        Write-Host ''
        Write-Host 'Etapa lista para firmar; no se instaló nada.'
        Write-Host "  Ruta: $stage"
        Write-Host "  Siguiente: Sign-Release.ps1 -TargetDir `"$stage`" -CertificateThumbprint <huella>"
        $ownedStage = $false
        return
    }

    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Ejecute la instalación desde un shell con privilegios de administrador.'
    }

    $manifestPath = Join-Path $stage $manifestName
    if (Test-Path -LiteralPath $manifestPath) {
        Write-Host 'Verificando integridad y firmas del paquete antes de aplicarlo...'
        try {
            & (Join-Path $PSScriptRoot 'Verify-Release.ps1') -TargetDir $stage -ManifestPath $manifestPath -ExpectedSignerSha256 $ExpectedSignerSha256 -AllowUntrustedTestSigner:$AllowUntrustedTestSigner
            if (-not $?) { throw 'Verify-Release.ps1 devolvió un error.' }
        }
        catch {
            throw "El paquete no superó la verificación; no se aplicó. $($_.Exception.Message)"
        }
    }
    elseif ($AllowUnsigned) {
        Write-Warning "Paquete sin ${manifestName}: se instala solo porque se indicó -AllowUnsigned."
    }
    else {
        throw "No hay $manifestName en $stage. Genere un paquete firmado o indique -AllowUnsigned explícitamente."
    }

    if ($BackupDir -and (Test-Path -LiteralPath $BackupDir)) {
        throw "BackupDir ya existe; no se sobrescribirá: $BackupDir"
    }

    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    # La ACL se aplica antes de escribir cualquier archivo de estado.
    Set-RestrictedAcl $DataDir 'del directorio de estado'

    $separator = [IO.Path]::DirectorySeparatorChar
    $running = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($InstallDir + $separator, [StringComparison]::OrdinalIgnoreCase) })
    if ($running.Count -gt 0) {
        throw "Hay procesos de Aegis Guard ejecutándose desde $InstallDir. Deténgalos antes de actualizar."
    }

    # Intercambio a nivel de directorio: si falla cualquier copia se restaura
    # la instalación anterior. El directorio de estado nunca se toca.
    $backup = $null
    if (Test-Path -LiteralPath $InstallDir) {
        $backup = $InstallDir + '.backup-' + [Guid]::NewGuid().ToString('N')
        Move-Item -LiteralPath $InstallDir -Destination $backup
        $replaced = $true
    }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $stage '*') -Destination $InstallDir -Recurse -Force

    if ($backup -and $BackupDir) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $BackupDir) | Out-Null
        Move-Item -LiteralPath $backup -Destination $BackupDir
        # Solo se restringe el backup; nunca el directorio padre, que puede ser compartido.
        Set-RestrictedAcl $BackupDir 'del backup'
        $retainedBackup = $BackupDir
        $backup = $null
        Write-Host "  Backup de la versión anterior: $BackupDir"
    }
    elseif ($backup) {
        Remove-Item -LiteralPath $backup -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $backup) { Write-Warning "La copia anterior no se pudo eliminar: $backup" }
    }

    Write-Host ''
    Write-Host 'Archivos instalados; el producto no usa credenciales ni servicios externos.'
    Write-Host "  Producto: $InstallDir"
    Write-Host "  Estado:   $DataDir"
    Write-Host "  Reglas:   $(Join-Path $InstallDir 'rules')"
    Write-Host ''
    Write-Host 'Para reforzar permisos, registrar el servicio SCM con inicio automático y crear accesos directos, ejecute como administrador:'
    Write-Host "  $(Join-Path $PSScriptRoot 'finish.cmd') `"$InstallDir`" `"$DataDir`""
}
catch {
    if ($replaced) {
        if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
        $restoreFrom = $null
        if ($backup -and (Test-Path -LiteralPath $backup)) { $restoreFrom = $backup }
        elseif ($retainedBackup -and (Test-Path -LiteralPath $retainedBackup)) { $restoreFrom = $retainedBackup }
        if ($restoreFrom) {
            Move-Item -LiteralPath $restoreFrom -Destination $InstallDir
            Write-Warning "Instalación restaurada desde $restoreFrom"
        }
        else {
            Write-Warning 'No había copia anterior; la instalación nueva no quedó aplicada.'
        }
    }
    throw
}
finally {
    if ($ownedStage -and $stage -and (Test-Path -LiteralPath $stage)) {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

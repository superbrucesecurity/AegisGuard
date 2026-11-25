[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetDir,
    [string]$ManifestPath,
    [string]$ExpectedSignerSha256,
    [switch]$AllowUntrustedTestSigner,
    [switch]$AllowUnpinnedSigner
)

$ErrorActionPreference = 'Stop'

$TargetDir = [IO.Path]::GetFullPath($TargetDir)
if (-not (Test-Path -LiteralPath $TargetDir -PathType Container)) { throw "No se encontró TargetDir: $TargetDir" }
if ([string]::IsNullOrWhiteSpace($ManifestPath)) { $ManifestPath = Join-Path $TargetDir 'RELEASE-SIGNATURES.json' }
$ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "No se encontró el manifiesto: $ManifestPath" }

$separator = [IO.Path]::DirectorySeparatorChar
$acceptedStatuses = @('Valid')
if ($AllowUntrustedTestSigner) {
    $acceptedStatuses += @('UnknownError', 'UntrustedRoot', 'NotTrusted')
    Write-Warning 'Modo laboratorio: se aceptan firmas sin cadena de confianza; no use este paquete en producción.'
}
$prefix = if ($TargetDir.EndsWith($separator)) { $TargetDir } else { $TargetDir + $separator }
$manifestFullName = $ManifestPath.TrimEnd($separator)
$stampPath = Join-Path $TargetDir 'RELEASE-SIGNATURES.ps1'
$stampFullName = $stampPath.TrimEnd($separator)

function Get-FileSha256([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Get-CertificateSha256($Certificate) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Certificate.RawData)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-SafeFullPath([string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative)) { throw 'El manifiesto contiene una ruta vacía.' }
    if ($Relative -match '^[A-Za-z]:' -or $Relative.StartsWith('\\') -or $Relative.StartsWith('/')) {
        throw "Ruta absoluta rechazada en el manifiesto: $Relative"
    }
    $normalized = $Relative.Replace('/', '\')
    $segments = @($normalized.Split('\'))
    if (@($segments | Where-Object { $_ -in @('', '.', '..') }).Count -gt 0) {
        throw "Ruta insegura en el manifiesto: $Relative"
    }
    $cursor = $TargetDir
    foreach ($segment in $segments) {
        $cursor = Join-Path $cursor $segment
        if (-not (Test-Path -LiteralPath $cursor)) { throw "Falta el fichero del manifiesto: $Relative" }
        $item = Get-Item -LiteralPath $cursor -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Se rechaza un enlace/reparse point en el manifiesto: $Relative"
        }
    }
    $full = [IO.Path]::GetFullPath($cursor)
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "La ruta escapa del paquete: $Relative"
    }
    return $full
}

$raw = Get-Content -LiteralPath $ManifestPath -Raw
try { $manifest = $raw | ConvertFrom-Json } catch { throw "El manifiesto no es JSON válido: $($_.Exception.Message)" }
foreach ($required in @('schema', 'version', 'signerCertificateSha256', 'files')) {
    if ($manifest.PSObject.Properties.Name -notcontains $required) { throw "Falta el campo $required en el manifiesto." }
}
if ($manifest.schema -ne 'aegis-release-manifest/1') { throw "Esquema de manifiesto no reconocido: $($manifest.schema)" }
if ($manifest.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+') { throw "Versión de manifiesto no válida: $($manifest.version)" }
if ($manifest.signerCertificateSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'signerCertificateSha256 no es un SHA-256 válido.' }
$manifestSigner = $manifest.signerCertificateSha256.ToLowerInvariant()

$expected = $ExpectedSignerSha256
if ([string]::IsNullOrWhiteSpace($expected)) { $expected = $env:AEGIS_RELEASE_SIGNER_SHA256 }
if ([string]::IsNullOrWhiteSpace($expected)) {
    if (-not $AllowUnpinnedSigner) {
        throw 'No se fijó la huella SHA-256 del firmante. Pase -ExpectedSignerSha256 o defina AEGIS_RELEASE_SIGNER_SHA256; solo se permite omitirla con -AllowUnpinnedSigner en laboratorio.'
    }
    Write-Warning 'Modo laboratorio: no se aplica key pinning externo; no instale este paquete en producción.'
}
else {
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') { throw 'ExpectedSignerSha256 no es un SHA-256 válido.' }
    if ($expected.ToLowerInvariant() -ne $manifestSigner) {
        throw "El certificado del paquete ($manifestSigner) no coincide con la huella fijada ($($expected.ToLowerInvariant()))."
    }
}

$versionPath = Join-Path $TargetDir 'VERSION'
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) { throw 'Falta VERSION en el paquete.' }
$installedVersion = (Get-Content -LiteralPath $versionPath -Raw).Trim()
if ($installedVersion -ne $manifest.version) {
    throw "VERSION ($installedVersion) no coincide con el manifiesto ($($manifest.version))."
}

if (-not (Test-Path -LiteralPath $stampPath -PathType Leaf)) {
    throw 'Falta RELEASE-SIGNATURES.ps1: el manifiesto no tiene un sello Authenticode.'
}
$stampSignature = Get-AuthenticodeSignature -LiteralPath $stampPath
if ($acceptedStatuses -notcontains $stampSignature.Status) {
    throw "Sello del manifiesto no válido: $($stampSignature.Status) ($($stampSignature.StatusMessage))"
}
if ($null -eq $stampSignature.SignerCertificate) { throw 'El sello del manifiesto no tiene certificado firmante.' }
if ((Get-CertificateSha256 $stampSignature.SignerCertificate) -ne $manifestSigner) {
    throw 'El sello del manifiesto fue firmado por otro certificado.'
}
if ($manifest.PSObject.Properties.Name -contains 'requiredSignerThumbprint') {
    $requiredThumb = ([string]$manifest.requiredSignerThumbprint).Replace(' ', '').ToUpperInvariant()
    if ($requiredThumb -notmatch '^[0-9A-F]{40}$') { throw 'requiredSignerThumbprint del manifiesto no es una huella SHA-1 válida.' }
    $actualThumb = $stampSignature.SignerCertificate.Thumbprint.ToUpperInvariant()
    if ($requiredThumb -ne $actualThumb) {
        throw "requiredSignerThumbprint ($requiredThumb) no coincide con el certificado que firmó el manifiesto ($actualThumb)."
    }
}
$stampHashes = @(Get-Content -LiteralPath $stampPath |
    Where-Object { $_ -match '^# sha256:([0-9a-fA-F]{64})$' } | ForEach-Object { $Matches[1].ToLowerInvariant() })
if ($stampHashes.Count -ne 1) { throw 'El sello del manifiesto debe declarar exactamente un SHA-256.' }
$manifestHash = Get-FileSha256 $ManifestPath
if ($stampHashes[0] -ne $manifestHash) { throw 'El manifiesto fue modificado después de firmarse.' }

$entries = @($manifest.files)
if ($entries.Count -eq 0) { throw 'El manifiesto no declara ficheros.' }
$seen = @{}
$signedCount = 0
$dataCount = 0
$thirdPartyCount = 0
$signable = @('.exe', '.dll', '.ps1')
foreach ($entry in $entries) {
    if ($entry.PSObject.Properties.Name -notcontains 'path' -or $entry.PSObject.Properties.Name -notcontains 'sha256') {
        throw 'Cada entrada del manifiesto debe tener path y sha256.'
    }
    if ($entry.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Hash no válido para $($entry.path)." }
    $key = ([string]$entry.path).Replace('/', '\').ToLowerInvariant()
    if ($seen.ContainsKey($key)) { throw "Ruta duplicada en el manifiesto: $($entry.path)" }
    $seen[$key] = $true
    $full = Get-SafeFullPath ([string]$entry.path)
    $actual = Get-FileSha256 $full
    if ($actual -ne $entry.sha256.ToLowerInvariant()) { throw "Hash no coincide: $($entry.path)" }

    $isSignable = ($signable -contains [IO.Path]::GetExtension($full).ToLowerInvariant())
    $signature = Get-AuthenticodeSignature -LiteralPath $full
    if ($isSignable) {
        if ($acceptedStatuses -notcontains $signature.Status) {
            throw "Firma no válida en $($entry.path): $($signature.Status) ($($signature.StatusMessage))"
        }
        if ($null -eq $signature.SignerCertificate) { throw "Sin certificado firmante en $($entry.path)." }
        $actualCertSha = Get-CertificateSha256 $signature.SignerCertificate
        if ($entry.PSObject.Properties.Name -contains 'signerCertificateSha256') {
            # Las dependencias de terceros conservan su firma original; no se
            # exige que usen la clave del publicador, pero sí que sea la misma
            # declarada en el manifiesto sellado.
            if ($entry.signerCertificateSha256.ToLowerInvariant() -ne $actualCertSha) {
                throw "El manifiesto declara otro certificado para $($entry.path)."
            }
        }
        elseif ($actualCertSha -ne $manifestSigner) {
            throw "Certificado firmante inesperado en $($entry.path): $actualCertSha"
        }
        if ($actualCertSha -eq $manifestSigner) { $signedCount++ } else { $thirdPartyCount++ }
    }
    elseif ($signature.Status -eq 'Valid') {
        $thirdPartyCount++
    }
    else {
        $dataCount++
    }
}

$actualFiles = @(Get-ChildItem -LiteralPath $TargetDir -Recurse -File -Force |
    Where-Object { $_.FullName.TrimEnd($separator) -ine $manifestFullName -and
                   $_.FullName.TrimEnd($separator) -ine $stampFullName })
foreach ($file in $actualFiles) {
    $relative = $file.FullName.Substring($prefix.Length)
    if (-not $seen.ContainsKey($relative.ToLowerInvariant())) {
        throw "Fichero no declarado en el manifiesto: $relative"
    }
}

if ($manifest.PSObject.Properties.Name -contains 'counted') {
    $counted = $manifest.counted
    foreach ($field in @('signedByUs', 'validThirdParty', 'unsignedData')) {
        if ($counted.PSObject.Properties.Name -contains $field) {
            $declared = [int]$counted.$field
            $observed = switch ($field) { 'signedByUs' { $signedCount } 'validThirdParty' { $thirdPartyCount } default { $dataCount } }
            if ($declared -ne $observed) { throw "Recuento $field no coincide: manifiesto $declared, paquete $observed." }
        }
    }
}

Write-Host "Paquete verificado: $($manifest.version) | $($entries.Count) ficheros | $signedCount firmados por la clave fijada | $thirdPartyCount con firma de terceros | $dataCount datos." -ForegroundColor Green
if (-not [string]::IsNullOrWhiteSpace($expected)) {
    Write-Host "Huella fijada verificada: $manifestSigner"
}
else {
    Write-Warning 'No se fijó AEGIS_RELEASE_SIGNER_SHA256: se comprobó la cadena de confianza y la coherencia del manifiesto, pero no se aplicó key pinning externo.'
}

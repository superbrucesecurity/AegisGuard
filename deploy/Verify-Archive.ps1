[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,
    [string]$StampPath,
    [string]$ExpectedSignerSha256,
    [switch]$AllowUntrustedTestSigner,
    [switch]$AllowUnpinnedSigner,
    [switch]$SkipPackageContents
)

$ErrorActionPreference = 'Stop'
$separator = [IO.Path]::DirectorySeparatorChar
$OutputDir = [IO.Path]::GetFullPath($OutputDir).TrimEnd($separator)
if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) { throw "No se encontró OutputDir: $OutputDir" }
if ([string]::IsNullOrWhiteSpace($StampPath)) {
    $stamps = @(Get-ChildItem -LiteralPath $OutputDir -File -Filter '*.stamp.ps1' -ErrorAction SilentlyContinue)
    if ($stamps.Count -ne 1) { throw 'Debe haber exactamente un archivo *.stamp.ps1 en OutputDir.' }
    $StampPath = $stamps[0].FullName
}
$StampPath = [IO.Path]::GetFullPath($StampPath)
if (-not (Test-Path -LiteralPath $StampPath -PathType Leaf)) { throw "No se encontró el sello: $StampPath" }

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

$acceptedStatuses = @('Valid')
if ($AllowUntrustedTestSigner) {
    $acceptedStatuses += @('UnknownError', 'UntrustedRoot', 'NotTrusted')
    Write-Warning 'Modo laboratorio: se acepta un sello sin cadena de confianza; no use este paquete en producción.'
}

$signature = Get-AuthenticodeSignature -LiteralPath $StampPath
if ($acceptedStatuses -notcontains $signature.Status) {
    throw "Sello del ZIP no válido: $($signature.Status) ($($signature.StatusMessage))"
}
if ($null -eq $signature.SignerCertificate) { throw 'El sello del ZIP no tiene certificado firmante.' }
$signerSha = Get-CertificateSha256 $signature.SignerCertificate

$expected = $ExpectedSignerSha256
if ([string]::IsNullOrWhiteSpace($expected)) { $expected = $env:AEGIS_RELEASE_SIGNER_SHA256 }
if ([string]::IsNullOrWhiteSpace($expected)) {
    if (-not $AllowUnpinnedSigner) {
        throw 'No se fijó la huella SHA-256 del firmante del ZIP. Pase -ExpectedSignerSha256 o defina AEGIS_RELEASE_SIGNER_SHA256; solo se permite omitirla con -AllowUnpinnedSigner en laboratorio.'
    }
    Write-Warning 'Modo laboratorio: no se aplica key pinning externo al ZIP; no publique este paquete.'
}
else {
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') { throw 'ExpectedSignerSha256 no es un SHA-256 válido.' }
    if ($expected.ToLowerInvariant() -ne $signerSha) {
        throw "El sello usa $signerSha, pero la huella fijada es $($expected.ToLowerInvariant())."
    }
}

$lines = @(Get-Content -LiteralPath $StampPath)
function Get-StampValue([string]$Prefix) {
    $found = @($lines | Where-Object { $_.StartsWith($Prefix) } | ForEach-Object { $_.Substring($Prefix.Length).Trim() })
    if ($found.Count -ne 1) { throw "El sello debe declarar exactamente una vez $Prefix" }
    return $found[0]
}

if ((Get-StampValue '# schema:') -ne 'aegis-release-archive/1') { throw 'Esquema de sello de ZIP no reconocido.' }
$zipName = Get-StampValue '# file:'
if ([string]::IsNullOrWhiteSpace($zipName) -or $zipName -match '[\\/]' -or $zipName -eq '.' -or $zipName -eq '..') {
    throw "Nombre de ZIP no seguro en el sello: $zipName"
}
$zipSha = Get-StampValue '# sha256:'
if ($zipSha -notmatch '^[0-9a-fA-F]{64}$') { throw 'El sello no declara un SHA-256 válido.' }
$declaredSigner = @($lines | Where-Object { $_.StartsWith('# signerSha256:') } | ForEach-Object { $_.Substring(15).Trim().ToLowerInvariant() })
if ($declaredSigner.Count -gt 1) { throw 'El sello declara varias huellas de firmante.' }
if ($declaredSigner.Count -eq 1 -and $declaredSigner[0] -ne $signerSha) {
    throw 'La huella declarada en el sello no coincide con el certificado firmante.'
}

$zipPath = Join-Path $OutputDir $zipName
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) { throw "No se encontró el ZIP: $zipPath" }
$actualSha = Get-FileSha256 $zipPath
if ($actualSha -ne $zipSha.ToLowerInvariant()) {
    throw "El ZIP fue modificado: esperado $zipSha, real $actualSha"
}
Write-Host "ZIP verificado: $zipName"
Write-Host "SHA-256: $actualSha"
Write-Host "Firmante: $signerSha"

if (-not $SkipPackageContents) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $temp = Join-Path $env:TEMP ('aegis-archive-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Force -Path $temp | Out-Null
        [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $temp)
        & (Join-Path $PSScriptRoot 'Verify-Release.ps1') -TargetDir $temp -ExpectedSignerSha256 $signerSha -AllowUntrustedTestSigner:$AllowUntrustedTestSigner
    }
    finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host 'Sello y contenido del paquete verificados.'

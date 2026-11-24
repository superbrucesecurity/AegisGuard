[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetDir,
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [SecureString]$PfxPassword,
    [string]$ManifestPath,
    [switch]$AllowUntrustedTestSigner
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$TargetDir = [IO.Path]::GetFullPath($TargetDir).TrimEnd([IO.Path]::DirectorySeparatorChar)
if (-not (Test-Path -LiteralPath $TargetDir -PathType Container)) { throw "No se encontró TargetDir: $TargetDir" }
if ([string]::IsNullOrWhiteSpace($ManifestPath)) { $ManifestPath = Join-Path $TargetDir 'RELEASE-SIGNATURES.json' }
$ManifestPath = [IO.Path]::GetFullPath($ManifestPath)
$stampPath = Join-Path $TargetDir 'RELEASE-SIGNATURES.ps1'

function Get-Certificate {
    if (-not [string]::IsNullOrWhiteSpace($PfxPath)) {
        if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) { throw "No se encontró el PFX: $PfxPath" }
        if ($null -eq $PfxPassword) { $PfxPassword = Read-Host 'Contraseña del PFX' -AsSecureString }
        return Import-PfxCertificate -FilePath $PfxPath -Password $PfxPassword -CertStoreLocation 'Cert:\CurrentUser\My'
    }
    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        throw 'Indique -CertificateThumbprint o -PfxPath.'
    }
    $wanted = ($CertificateThumbprint -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
    if ($wanted.Length -ne 40) { throw 'CertificateThumbprint debe ser una huella SHA-1 de 40 hexadecimales.' }
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        foreach ($candidate in Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue) {
            if ($candidate.Thumbprint -ieq $wanted) { return $candidate }
        }
    }
    throw "No se encontró el certificado $wanted en los almacenes personales."
}

$cert = Get-Certificate
if (-not $cert.HasPrivateKey) { throw 'El certificado indicado no tiene clave privada; no puede firmar.' }
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$eku = @($cert.EnhancedKeyUsageList | ForEach-Object {
    if ($_.ObjectId -is [string]) { $_.ObjectId } else { $_.ObjectId.Value }
})
if ($eku -notcontains $codeSigningOid) { throw 'El certificado no tiene el uso extendido de firma de código.' }
$pin = $cert.Thumbprint.ToUpperInvariant()
$certHasher = [Security.Cryptography.SHA256]::Create()
try { $certSha256 = [BitConverter]::ToString($certHasher.ComputeHash($cert.RawData)).Replace('-', '').ToLowerInvariant() }
finally { $certHasher.Dispose() }

$signable = @('.exe', '.dll', '.ps1')
$acceptedStatuses = @('Valid')
if ($AllowUntrustedTestSigner) {
    $acceptedStatuses += @('UnknownError', 'UntrustedRoot', 'NotTrusted')
    Write-Warning 'Modo laboratorio: se aceptarán firmas sin cadena de confianza. No use el paquete resultante en producción.'
}
$files = @(Get-ChildItem -LiteralPath $TargetDir -File -Recurse -Force |
    Where-Object { $_.FullName -ine $ManifestPath -and $_.FullName -ine $stampPath } | Sort-Object FullName)
$entries = @()
$ours = 0
$thirdParty = 0
$dataFiles = 0
foreach ($file in $files) {
    $relative = $file.FullName.Substring($TargetDir.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    if ($signable -contains $file.Extension.ToLowerInvariant()) {
        if ($signature.Status -eq 'NotSigned') {
            $null = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
            if ($acceptedStatuses -notcontains $signature.Status) {
                throw "No se pudo firmar ${relative}: $($signature.Status) - $($signature.StatusMessage)"
            }
            $ours++
        }
        elseif ($acceptedStatuses -contains $signature.Status -and $null -ne $signature.SignerCertificate) {
            $existingHasher = [Security.Cryptography.SHA256]::Create()
            try {
                $existingSha = [BitConverter]::ToString($existingHasher.ComputeHash($signature.SignerCertificate.RawData)).Replace('-', '').ToLowerInvariant()
            }
            finally { $existingHasher.Dispose() }
            if ($existingSha -eq $certSha) { $ours++ } else { $thirdParty++ }
        }
        else {
            throw "Firma en estado $($signature.Status) en ${relative}: $($signature.StatusMessage)"
        }
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($file.FullName))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $entry = [ordered]@{ path = $relative; sha256 = $hash }
    if ($acceptedStatuses -contains $signature.Status -and $null -ne $signature.SignerCertificate) {
        $signerHasher = [Security.Cryptography.SHA256]::Create()
        try {
            $signerSha = [BitConverter]::ToString($signerHasher.ComputeHash($signature.SignerCertificate.RawData)).Replace('-', '').ToLowerInvariant()
        }
        finally { $signerHasher.Dispose() }
        $entry.signerThumbprint = $signature.SignerCertificate.Thumbprint.ToUpperInvariant()
        $entry.signerCertificateSha256 = $signerSha
        $entry.signatureStatus = [string]$signature.Status
    }
    elseif ($signable -notcontains $file.Extension.ToLowerInvariant()) {
        $dataFiles++
    }
    $entries += [pscustomobject]$entry
}

$props = Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw
if ($props -notmatch '<Version>([^<]+)</Version>') { throw 'No se encontró <Version> en Directory.Build.props.' }
$manifest = [ordered]@{
    schema = 'aegis-release-manifest/1'
    version = $Matches[1].Trim()
    createdAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
    requiredSignerThumbprint = $pin
    signerCertificateSha256 = $certSha256
    signerSubject = $cert.Subject
    counted = [ordered]@{
        signedByUs = $ours
        validThirdParty = $thirdParty
        unsignedData = $dataFiles
    }
    notes = 'Firma Authenticode sin marca de tiempo: la validez depende del certificado y de su cadena de confianza. Los hashes SHA-256 se comprueban antes de instalar.'
    files = @($entries)
}
$json = $manifest | ConvertTo-Json -Depth 12
[IO.File]::WriteAllText($ManifestPath, $json + "`r`n", (New-Object Text.UTF8Encoding($false)))

# Sello independiente: Authenticode no puede firmar JSON directamente, así que
# se firma un script que declara el hash del manifiesto. Así los ficheros sin
# firma propia (reglas, listas, documentos) quedan protegidos contra edición.
$manifestStream = [IO.File]::Open($ManifestPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    $manifestHasher = [Security.Cryptography.SHA256]::Create()
    try { $manifestHash = [BitConverter]::ToString($manifestHasher.ComputeHash($manifestStream)).Replace('-', '').ToLowerInvariant() }
    finally { $manifestHasher.Dispose() }
}
finally { $manifestStream.Dispose() }
$stamp = "# Aegis Guard release manifest stamp`r`n# schema: aegis-release-manifest/1`r`n# sha256:$manifestHash`r`n"
[IO.File]::WriteAllText($stampPath, $stamp, (New-Object Text.UTF8Encoding($false)))
$null = Set-AuthenticodeSignature -FilePath $stampPath -Certificate $cert
$stampSignature = Get-AuthenticodeSignature -LiteralPath $stampPath
if ($acceptedStatuses -notcontains $stampSignature.Status) {
    throw "No se pudo firmar el sello del manifiesto: $($stampSignature.Status) ($($stampSignature.StatusMessage))"
}

Write-Host "Manifest: $ManifestPath"
Write-Host "Sello firmado: $stampPath"
Write-Host "Huella SHA-1 del certificado: $pin"
Write-Host "Huella SHA-256 para fijar en AEGIS_RELEASE_SIGNER_SHA256: $certSha256"
Write-Host "Firmados por esta clave: $ours | terceros válidos: $thirdParty | datos sin firma: $dataFiles"
Write-Host "IMPORTANTE: compruebe que $pin es la huella de su certificado de publicación antes de distribuir el paquete."

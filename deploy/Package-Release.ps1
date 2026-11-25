[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDir,
    [string]$OutputDir,
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [SecureString]$PfxPassword,
    [string]$ExpectedSignerSha256,
    [switch]$AllowUntrustedTestSigner,
    [switch]$AllowUnpinnedSigner
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Aegis-DeployCommon.ps1')

$separator = [IO.Path]::DirectorySeparatorChar
$PackageDir = [IO.Path]::GetFullPath($PackageDir).TrimEnd($separator)
if (-not (Test-Path -LiteralPath $PackageDir -PathType Container)) { throw "No se encontró PackageDir: $PackageDir" }
if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = Split-Path -Parent $PackageDir }
$OutputDir = [IO.Path]::GetFullPath($OutputDir).TrimEnd($separator)
if ($OutputDir.Equals($PackageDir, [StringComparison]::OrdinalIgnoreCase) -or
    $OutputDir.StartsWith($PackageDir + $separator, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputDir no puede ser PackageDir ni estar dentro de él.'
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$acceptedStatuses = @('Valid')
if ($AllowUntrustedTestSigner) {
    $acceptedStatuses += @('UnknownError', 'UntrustedRoot', 'NotTrusted')
    Write-Warning 'Modo laboratorio: el sello del ZIP se aceptará sin cadena de confianza. No publique este paquete.'
}

# El ZIP solo se crea si el paquete interior supera la misma verificación que aplica el instalador.
& (Join-Path $PSScriptRoot 'Verify-Release.ps1') -TargetDir $PackageDir -ExpectedSignerSha256 $ExpectedSignerSha256 -AllowUntrustedTestSigner:$AllowUntrustedTestSigner -AllowUnpinnedSigner:$AllowUnpinnedSigner

$manifestPath = Join-Path $PackageDir 'RELEASE-SIGNATURES.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$version = [string]$manifest.version
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') { throw "Versión de paquete no válida: $version" }
$signer = ([string]$manifest.signerCertificateSha256).ToLowerInvariant()

$cert = Get-AegisSigningCertificate -CertificateThumbprint $CertificateThumbprint -PfxPath $PfxPath -PfxPassword $PfxPassword
if (-not $cert.HasPrivateKey) { throw 'El certificado indicado no tiene clave privada; no puede firmar.' }
$codeSigningOid = '1.3.6.1.5.5.7.3.3'
$eku = @($cert.EnhancedKeyUsageList | ForEach-Object {
    if ($_.ObjectId -is [string]) { $_.ObjectId } else { $_.ObjectId.Value }
})
if ($eku -notcontains $codeSigningOid) { throw 'El certificado no tiene el uso extendido de firma de código.' }
$certSha = Get-AegisCertificateSha256 $cert
if ($certSha -ne $signer) {
    throw "El certificado elegido ($certSha) no es el que firmó el paquete ($signer)."
}

# Authenticode no puede firmar un ZIP de forma verificable por Windows, así que
# se publica un sello .ps1 independiente con el SHA-256 del archivo.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipName = "AegisGuard-$version-win-x64.zip"
$zipPath = Join-Path $OutputDir $zipName
if (Test-Path -LiteralPath $zipPath -PathType Leaf) { Remove-Item -LiteralPath $zipPath -Force }
[IO.Compression.ZipFile]::CreateFromDirectory($PackageDir, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $false)
$zipSha = Get-AegisFileSha256 $zipPath

$hashPath = Join-Path $OutputDir ($zipName + '.sha256')
[IO.File]::WriteAllText($hashPath, "$zipSha  $zipName`r`n", (New-Object Text.UTF8Encoding($false)))

$stampName = "AegisGuard-$version-win-x64.stamp.ps1"
$stampPath = Join-Path $OutputDir $stampName
$stamp = "# Aegis Guard release archive stamp`r`n" +
         "# schema: aegis-release-archive/1`r`n" +
         "# file:$zipName`r`n" +
         "# sha256:$zipSha`r`n" +
         "# signerSha256:$signer`r`n"
[IO.File]::WriteAllText($stampPath, $stamp, (New-Object Text.UTF8Encoding($false)))
$null = Set-AuthenticodeSignature -FilePath $stampPath -Certificate $cert
$signature = Get-AuthenticodeSignature -LiteralPath $stampPath
if ($acceptedStatuses -notcontains $signature.Status) {
    throw "No se pudo firmar el sello del ZIP: $($signature.Status) ($($signature.StatusMessage))"
}
if ($null -eq $signature.SignerCertificate) { throw 'El sello del ZIP no tiene certificado firmante.' }
if ((Get-AegisCertificateSha256 $signature.SignerCertificate) -ne $signer) {
    throw 'El sello del ZIP fue firmado por otro certificado.'
}

# El ZIP se verifica de nuevo desde fuera, incluido el contenido interior, para
# cerrar la ventana entre la verificación de la etapa y la creación del archivo.
& (Join-Path $PSScriptRoot 'Verify-Archive.ps1') -OutputDir $OutputDir -StampPath $stampPath `
    -ExpectedSignerSha256 $ExpectedSignerSha256 `
    -AllowUntrustedTestSigner:$AllowUntrustedTestSigner `
    -AllowUnpinnedSigner:$AllowUnpinnedSigner
if (-not $?) { throw 'Verify-Archive.ps1 no validó el ZIP recién creado.' }

Write-Host "ZIP: $zipPath"
Write-Host "SHA-256: $zipSha"
Write-Host "Sello firmado: $stampPath"
Write-Host "Hash sin firma: $hashPath"

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SigningKeyPath,
    [string]$RulesDir,
    [string]$OutputPath,
    [string]$Version = '1.0.0'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($RulesDir)) { $RulesDir = Join-Path $root 'rules' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'artifacts\intel-package' }
if (-not (Test-Path -LiteralPath $RulesDir -PathType Container)) { throw "No existe RulesDir: $RulesDir" }
if (-not (Test-Path -LiteralPath $SigningKeyPath -PathType Leaf)) { throw "No existe la clave de firma: $SigningKeyPath" }

Add-Type -AssemblyName System.Security

function Convert-FromHex {
    param([Parameter(Mandatory = $true)][string]$Hex)
    if ($Hex.Length % 2 -ne 0) { throw 'Hexadecimal con número impar de caracteres.' }
    $result = New-Object 'byte[]' ($Hex.Length / 2)
    for ($i = 0; $i -lt $result.Length; $i++) {
        $result[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $result
}

function Convert-ToHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $builder = New-Object Text.StringBuilder ($Bytes.Length * 2)
    foreach ($byte in $Bytes) { [void]$builder.Append($byte.ToString('x2')) }
    return $builder.ToString()
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return $sha.ComputeHash($Bytes) }
    finally { $sha.Dispose() }
}

$keyJson = Get-Content -LiteralPath $SigningKeyPath -Raw | ConvertFrom-Json
if ($keyJson.algorithm -ne 'ECDSA-P256' -or -not $keyJson.d -or -not $keyJson.x -or -not $keyJson.y) {
    throw 'La clave debe ser ECDSA-P256 con d, x e y en hexadecimal.'
}
$d = Convert-FromHex $keyJson.d
$x = Convert-FromHex $keyJson.x
$y = Convert-FromHex $keyJson.y
$ecdsa = [System.Security.Cryptography.ECDsa]::Create(
    [System.Security.Cryptography.ECParameters]@{
        Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
        D = $d
        Q = [System.Security.Cryptography.ECPoint]@{ X = $x; Y = $y }
    }
)

$allowed = @('threat-intel.json', 'eicar.yar', 'suspicious_basics.yar')
$entries = @()
foreach ($name in $allowed) {
    $source = Join-Path $RulesDir $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
    $bytes = [IO.File]::ReadAllBytes($source)
    if ($bytes.Length -gt 16MB) { throw "Fichero demasiado grande: $name" }
    $entries += [pscustomobject]@{
        path = $name
        sha256 = Convert-ToHex (Get-Sha256 $bytes)
    }
}
if ($entries.Count -eq 0) { throw 'No hay ficheros de reglas para empaquetar.' }

$publicHash = Convert-ToHex (Get-Sha256 ($x + $y))
$manifest = [pscustomobject]@{
    version = $Version
    createdUtc = [DateTimeOffset]::UtcNow.ToString('o')
    files = $entries
}
$manifestBytes = [Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json -Depth 6))
$signature = $ecdsa.SignData($manifestBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$publicKey = [pscustomobject]@{
    algorithm = 'ECDSA-P256'
    x = $keyJson.x
    y = $keyJson.y
    sha256 = $publicHash
}

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
foreach ($entry in $entries) {
    Copy-Item -LiteralPath (Join-Path $RulesDir $entry.path) -Destination (Join-Path $OutputPath $entry.path) -Force
}
[IO.File]::WriteAllBytes((Join-Path $OutputPath 'manifest.json'), $manifestBytes)
[IO.File]::WriteAllText((Join-Path $OutputPath 'manifest.sig'), [Convert]::ToBase64String($signature))
[IO.File]::WriteAllText((Join-Path $OutputPath 'public-key.json'), ($publicKey | ConvertTo-Json -Depth 4))
Write-Host "Paquete de inteligencia $Version generado en $OutputPath ($($entries.Count) ficheros)."
Write-Host "Huella de clave para AEGIS_INTEL_KEY_SHA256: $publicHash"

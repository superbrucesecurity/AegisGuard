[CmdletBinding()]
param()

# Helpers compartidos por los scripts de publicación y verificación. Se
# dot-source desde cada script para que el paquete firmado sea autocontenido y
# no haya copias divergentes de la misma lógica.

function Get-AegisFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Get-AegisCertificateSha256 {
    param([Parameter(Mandatory = $true)]$Certificate)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Certificate.RawData)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-AegisSigningCertificate {
    param(
        [string]$CertificateThumbprint,
        [string]$PfxPath,
        [SecureString]$PfxPassword
    )
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

function Assert-AegisSafeDirectory {
    param([string]$Path, [string]$Label)
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
        throw "$Label no puede ser una raiz del sistema: $full"
    }
    return $full
}

function Get-AegisPrivilegedPipeName {
    param([Parameter(Mandatory = $true)][string]$Sid)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Sid))
    }
    finally { $sha.Dispose() }
    $pipeHash = -join ($hashBytes[0..7] | ForEach-Object { $_.ToString('x2') })
    return "aegisguard-$pipeHash-privileged"
}

function Invoke-Ipc {
    param(
        [Parameter(Mandatory = $true)][string]$PipeName,
        [Parameter(Mandatory = $true)][string]$Operation,
        [hashtable]$Payload = @{}
    )
    $request = @{ operation = $Operation; payload = $Payload } | ConvertTo-Json -Depth 12 -Compress
    $client = [IO.Pipes.NamedPipeClientStream]::new(
        '.', $PipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $client.Connect(10000)
        $bytes = [Text.Encoding]::UTF8.GetBytes($request + "`n")
        $client.Write($bytes, 0, $bytes.Length)
        $client.Flush()
        $reader = [IO.StreamReader]::new($client, [Text.Encoding]::UTF8, $false, 4096, $true)
        $line = $reader.ReadLine()
        if (-not $line) { throw "El canal $PipeName no devolvió respuesta para $Operation." }
        $response = $line | ConvertFrom-Json
        if (-not $response.ok) { throw "IPC $Operation rechazada: $($response.error)" }
        return $response.result
    }
    finally { $client.Dispose() }
}

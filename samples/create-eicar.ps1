[CmdletBinding()]
param(
    [string]$Path = "$env:USERPROFILE\Desktop\Aegis-EICAR-Test.txt"
)

$ErrorActionPreference = 'Stop'

# Se compone en tiempo de ejecución: muchos antivirus bloquean los archivos que
# contienen la firma literal, incluidos los propios scripts de generación.
$parts = @(
    'X5O!P%@AP[4',
    '\PZX54(P^)7CC)7}$EICAR-',
    'STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
)
$content = [string]::Concat($parts)

$directory = Split-Path -Parent $Path
if ($directory -and -not (Test-Path $directory)) { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
[IO.File]::WriteAllText($Path, $content, [Text.Encoding]::ASCII)

Write-Host "Muestra EICAR creada: $Path"
Write-Host 'Es inofensiva: los productos de seguridad deberían detectarla como prueba.'
Write-Host 'Algunos antivirus bloquean incluso su creación; en ese caso no desactive su producto: use el informe de Aegis Guard.'

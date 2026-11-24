[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [string]$ShortcutName = 'Aegis Guard'
)

$ErrorActionPreference = 'Stop'

$exe = Join-Path $InstallDir 'Aegis.UI\Aegis.UI.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "No se encontró $exe" }

$shell = New-Object -ComObject WScript.Shell
foreach ($folder in @('StartMenu', 'Desktop')) {
    $path = Join-Path ([Environment]::GetFolderPath($folder)) "$ShortcutName.lnk"
    $link = $shell.CreateShortcut($path)
    $link.TargetPath = $exe
    $link.WorkingDirectory = Split-Path -Parent $exe
    $link.Description = $ShortcutName
    $link.Save()
    Write-Host "Acceso directo: $path"
}

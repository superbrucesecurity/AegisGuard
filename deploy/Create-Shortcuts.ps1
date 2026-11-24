[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [string]$ShortcutName = 'Aegis Guard'
)

$ErrorActionPreference = 'Stop'

$exe = Join-Path $InstallDir 'Aegis.UI\Aegis.UI.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "No se encontró $exe" }
# run-ui.cmd conserva AEGIS_DATA_DIR en instalaciones aisladas.
$launcher = Join-Path $InstallDir 'run-ui.cmd'
$target = if (Test-Path -LiteralPath $launcher) { $launcher } else { $exe }

$shell = New-Object -ComObject WScript.Shell
foreach ($folder in @('StartMenu', 'Desktop')) {
    $path = Join-Path ([Environment]::GetFolderPath($folder)) "$ShortcutName.lnk"
    $link = $shell.CreateShortcut($path)
    $link.TargetPath = $target
    $link.WorkingDirectory = Split-Path -Parent $exe
    $link.IconLocation = "$exe,0"
    $link.Description = $ShortcutName
    $link.Save()
    Write-Host "Acceso directo: $path"
}

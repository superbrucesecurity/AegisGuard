[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$NoticePath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'SBOM.spdx.json' }
if ([string]::IsNullOrWhiteSpace($NoticePath)) { $NoticePath = Join-Path $root 'THIRD-PARTY-NOTICES.md' }

$props = Get-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Raw
if ($props -notmatch '<Version>([^<]+)</Version>') { throw 'No se encontró <Version> en Directory.Build.props.' }
$version = $Matches[1].Trim()

$list = (& dotnet list (Join-Path $root 'AegisGuard.slnx') package --include-transitive --format json | Out-String | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'dotnet list package falló.' }

$nugetRoot = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $env:USERPROFILE '.nuget\packages' }
function Get-License([string]$Id, [string]$Version) {
    $packageDir = Join-Path $nugetRoot (($Id + '\' + $Version).ToLowerInvariant())
    $nuspec = Get-ChildItem -LiteralPath $packageDir -Filter '*.nuspec' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $nuspec) { return 'NOASSERTION' }
    try {
        [xml]$xml = Get-Content -LiteralPath $nuspec.FullName -Raw
        $node = $xml.package.metadata.license
        if ($node -and $node.type -eq 'expression' -and $node.'#text') { return $node.'#text' }
        if ($node -and $node.type -eq 'file' -and $node.'#text') {
            $licenseFile = Join-Path $packageDir $node.'#text'
            if (Test-Path -LiteralPath $licenseFile -PathType Leaf) {
                $text = Get-Content -LiteralPath $licenseFile -Raw
                if ($text -match 'Redistribution and use in source and binary forms') {
                    if ($text -match 'endorse|promote products') { return 'BSD-3-Clause' }
                    return 'BSD-2-Clause'
                }
                if ($text -match 'Permission is hereby granted, free of charge') { return 'MIT' }
                if ($text -match 'Apache License') { return 'Apache-2.0' }
            }
            return 'LicenseRef-' + ($node.'#text' -replace '[^A-Za-z0-9.-]', '-')
        }
        if ($node -and $node.'#text') { return 'LicenseRef-' + ($node.'#text' -replace '[^A-Za-z0-9.-]', '-') }
        if ($xml.package.metadata.licenseUrl) { return 'LicenseRef-URL:' + $xml.package.metadata.licenseUrl }
    } catch { return 'NOASSERTION' }
    return 'NOASSERTION'
}

function Copy-LicenseFile([string]$Id, [string]$Version) {
    $packageDir = Join-Path $nugetRoot (($Id + '\' + $Version).ToLowerInvariant())
    $nuspec = Get-ChildItem -LiteralPath $packageDir -Filter '*.nuspec' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $nuspec) { return }
    try {
        [xml]$xml = Get-Content -LiteralPath $nuspec.FullName -Raw
        $node = $xml.package.metadata.license
        if (-not $node -or $node.type -ne 'file' -or -not $node.'#text') { return }
        $source = Join-Path $packageDir $node.'#text'
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { return }
        $licensesDir = Join-Path $root 'licenses'
        New-Item -ItemType Directory -Force -Path $licensesDir | Out-Null
        Copy-Item -LiteralPath $source -Destination (Join-Path $licensesDir ($Id + '-' + $Version + '.txt')) -Force
    } catch { return }
}

function New-SpdxId([string]$Id, [string]$Version) {
    $safe = ($Id + '-' + $Version) -replace '[^A-Za-z0-9.-]', '-'
    return 'SPDXRef-Package-' + $safe
}

$packages = @()
$relationships = @()
$productId = 'SPDXRef-Package-AegisGuard'
$product = [ordered]@{
    name = 'AegisGuard'
    SPDXID = $productId
    versionInfo = $version
    downloadLocation = 'NOASSERTION'
    filesAnalyzed = $false
    licenseConcluded = 'NOASSERTION'
    licenseDeclared = 'NOASSERTION'
    copyrightText = 'NOASSERTION'
    supplier = 'Organization: superbrucesecurity'
    description = 'Local Windows antivirus and firewall platform'
}
$packages += [pscustomobject]$product
$relationships += [pscustomobject]@{
    spdxElementId = 'SPDXRef-DOCUMENT'
    relatedSpdxElement = $productId
    relationshipType = 'DESCRIBES'
}

$noticeRows = @()
foreach ($project in $list.projects) {
    $isTest = $project.path -replace '\\', '/' -match '/tests/'
    foreach ($framework in $project.frameworks) {
        $all = @()
        foreach ($package in $framework.topLevelPackages) {
            $all += [pscustomobject]@{ id = $package.id; version = $package.resolvedVersion; topLevel = $true }
        }
        foreach ($package in $framework.transitivePackages) {
            if ($null -eq $package) { continue }
            $all += [pscustomobject]@{ id = $package.id; version = $package.resolvedVersion; topLevel = $false }
        }
        foreach ($package in $all) {
            $spdxId = New-SpdxId $package.id $package.version
            if ($packages.SPDXID -contains $spdxId) { continue }
            $license = Get-License $package.id $package.version
            Copy-LicenseFile $package.id $package.version
            $packages += [pscustomobject][ordered]@{
                name = $package.id
                SPDXID = $spdxId
                versionInfo = $package.version
                downloadLocation = 'https://www.nuget.org/packages/' + $package.id + '/' + $package.version
                filesAnalyzed = $false
                licenseConcluded = $license
                licenseDeclared = $license
                copyrightText = 'NOASSERTION'
                supplier = 'Organization: NuGet package publisher'
            }
            $relationships += [pscustomobject]@{
                spdxElementId = if ($isTest) { $spdxId } else { $productId }
                relatedSpdxElement = if ($isTest) { $productId } else { $spdxId }
                relationshipType = if ($isTest) { 'DEV_DEPENDENCY_OF' } else { 'DEPENDS_ON' }
            }
            $licenseFile = Join-Path (Join-Path $root 'licenses') ($package.id + '-' + $package.version + '.txt')
            $noticeRows += [pscustomobject]@{
                Package = $package.id
                Version = $package.version
                License = $license
                Scope = if ($isTest) { 'test' } else { 'runtime' }
                LicenseFile = if (Test-Path -LiteralPath $licenseFile) { 'licenses/' + $package.id + '-' + $package.version + '.txt' } else { '-' }
            }
        }
    }
}

$sbom = [ordered]@{
    spdxVersion = 'SPDX-2.3'
    dataLicense = 'CC0-1.0'
    SPDXID = 'SPDXRef-DOCUMENT'
    name = 'AegisGuard-' + $version
    documentNamespace = 'https://github.com/superbrucesecurity/AegisGuard/spdx/v' + $version
    creationInfo = [ordered]@{
        created = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        creators = @('Tool: AegisGuard-Generate-Sbom-1.0', 'Organization: superbrucesecurity')
    }
    documentDescribes = @($productId)
    packages = @($packages)
    relationships = @($relationships)
}
$json = $sbom | ConvertTo-Json -Depth 20
[IO.File]::WriteAllText($OutputPath, $json + "`r`n")

$lines = @(
    '# Aviso de terceros',
    '',
    "Generado para Aegis Guard $version con ``deploy/Generate-Sbom.ps1``. Las licencias se leen de los `.nuspec` de la caché NuGet local; `NOASSERTION` significa que el paquete no declara una expresión SPDX reconocible.",
    '',
    '| Paquete | Versión | Licencia declarada | Ámbito | Texto incluido |',
    '| --- | --- | --- | --- | --- |'
)
foreach ($row in ($noticeRows | Sort-Object Scope, Package, Version)) {
    $lines += "| $($row.Package) | $($row.Version) | $($row.License) | $($row.Scope) | $($row.LicenseFile) |"
}
$lines += @('', 'El código de Aegis Guard es propietario y se publica solo para transparencia y verificación; consulte LICENSE. Las dependencias de terceros conservan sus propias licencias. El producto no usa credenciales, telemetría ni servicios remotos.', '')
[IO.File]::WriteAllText($NoticePath, ($lines -join "`r`n"))

Write-Host "SBOM: $OutputPath ($($packages.Count) paquetes)."
Write-Host "Aviso: $NoticePath."

rule Ransomware_Note
{
    meta:
        severity = "high"
        description = "Posible nota de rescate"
    strings:
        $a = "YOUR FILES ARE ENCRYPTED" nocase
        $b = "ransom" nocase
        $c = "bitcoin" nocase
    condition:
        // Dos indicios evitan que la palabra suelta "ransom" dispare una alerta alta.
        2 of them
}

rule Mimikatz_Indicators
{
    meta:
        severity = "critical"
        description = "Indicadores de volcado de credenciales"
    strings:
        $a = "sekurlsa" nocase
        $b = "logonpasswords" nocase
        $c = { 4D 69 6D 69 6B 61 74 7A }
    condition:
        // "sekurlsa" aislado aparece en informes y documentación: exigir
        // las tres señales evita un falso positivo crítico.
        all of them
}

rule Encoded_PowerShell
{
    meta:
        severity = "medium"
        description = "PowerShell con carga codificada"
    strings:
        $a = "-enc" nocase
        $b = "FromBase64String" nocase
        $c = "IEX(" nocase
    condition:
        all of them
}

rule Suspicious_Office_Macro
{
    meta:
        severity = "medium"
        description = "Macro con autoarranque y ejecución externa"
    strings:
        $a = "Auto_Open" nocase
        $b = "Shell(" nocase
        $c = "CreateObject" nocase
    condition:
        all of them
}

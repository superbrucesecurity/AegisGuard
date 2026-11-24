namespace Aegis.Core;

/// <summary>
/// Topes explícitos del análisis local. Un único lugar para evitar que el
/// escáner, YARA, la cuarentena y los analizadores de Fase 3 usen límites
/// divergentes. Ninguno de estos valores es una medición de rendimiento.
/// </summary>
public static class AnalysisLimits
{
    /// <summary>Bytes que se leen como máximo por fichero para hash/EICAR/YARA.</summary>
    public const long MaxScanBytes = 512L * 1024 * 1024;

    /// <summary>Bytes que se conservan en memoria para analizadores estructurales.</summary>
    public const int MaxSnapshotBytes = 8 * 1024 * 1024;

    /// <summary>Bytes máximos de un script analizado en memoria.</summary>
    public const int MaxScriptBytes = 4 * 1024 * 1024;

    /// <summary>Bytes máximos de un archivo comprimido.</summary>
    public const long MaxArchiveBytes = 64L * 1024 * 1024;

    /// <summary>Número máximo de entradas recorridas en un archivo.</summary>
    public const int MaxArchiveEntries = 2048;

    /// <summary>Bytes descomprimidos máximos por entrada.</summary>
    public const long MaxArchiveMemberBytes = 32L * 1024 * 1024;

    /// <summary>Bytes descomprimidos totales máximos por archivo.</summary>
    public const long MaxArchiveTotalBytes = 128L * 1024 * 1024;

    /// <summary>Profundidad máxima de anidamiento de archivos.</summary>
    public const int MaxArchiveDepth = 3;

    /// <summary>Bytes máximos de cabeceras/tablas PE leídas.</summary>
    public const int MaxPeBytes = 1024 * 1024;

    /// <summary>Bytes máximos de un stream VBA/OLE analizado.</summary>
    public const long MaxMacroStreamBytes = 16L * 1024 * 1024;
}

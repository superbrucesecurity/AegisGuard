namespace Aegis.Core;

/// <summary>
/// Directorio de estado de la aplicación. AEGIS_DATA_DIR permite aislar una
/// instalación de prueba sin tocar C:\ProgramData; por defecto se usa ProgramData.
/// </summary>
public static class AegisPaths
{
    public static string DataRoot
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("AEGIS_DATA_DIR");
            return string.IsNullOrWhiteSpace(configured)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisGuard")
                : Path.GetFullPath(configured);
        }
    }
}

/// <summary>
/// Carga variables de entorno desde un archivo local restringido. Solo se
/// aplican variables que no estén ya definidas en el proceso, para permitir
/// overrides temporales durante pruebas o despliegues.
/// </summary>
public static class EnvFile
{
    public static string DefaultPath => Path.Combine(AegisPaths.DataRoot, "gateway.env");

    /// <summary>
    /// Carga solo las claves permitidas. El servicio no debe heredar
    /// LIQUID_API_KEY: la clave de Liquid pertenece exclusivamente al gateway.
    /// </summary>
    public static void Load(string? path = null, IReadOnlyCollection<string>? allowedKeys = null)
    {
        var file = path ?? DefaultPath;
        if (!File.Exists(file)) return;
        IEnumerable<string> lines;
        try
        {
            lines = File.ReadLines(file).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return;
        }

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var separator = line.IndexOf('=');
            if (separator <= 0) continue;
            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim().Trim('"', '\'');
            if (key.Length == 0 || value.Length == 0) continue;
            if (allowedKeys is not null && !allowedKeys.Contains(key)) continue;
            // Empty es un valor definido explícitamente (por ejemplo, para desactivar).
            if (Environment.GetEnvironmentVariable(key) is null)
                Environment.SetEnvironmentVariable(key, value, EnvironmentVariableTarget.Process);
        }
    }
}

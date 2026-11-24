namespace Aegis.Core;

/// <summary>
/// Carga variables de entorno desde un archivo local restringido. Solo se
/// aplican variables que no estén ya definidas en el proceso, para permitir
/// overrides temporales durante pruebas o despliegues.
/// </summary>
public static class EnvFile
{
    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "AegisGuard", "gateway.env");

    public static void Load(string? path = null)
    {
        var file = path ?? DefaultPath;
        if (!File.Exists(file)) return;
        foreach (var raw in File.ReadLines(file))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var separator = line.IndexOf('=');
            if (separator <= 0) continue;
            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim().Trim('"', '\'');
            if (key.Length == 0 || value.Length == 0) continue;
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(key)))
                Environment.SetEnvironmentVariable(key, value, EnvironmentVariableTarget.Process);
        }
    }
}

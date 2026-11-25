namespace Aegis.Core;

/// <summary>
/// Política de alcance para el análisis solicitado por un cliente local.
/// El servicio se ejecuta con privilegios, por lo que no debe aceptar una ruta
/// arbitraria: sólo se analizan los directorios explícitamente permitidos por
/// la instalación (perfil del usuario, temporales y raíces de prueba aisladas).
/// </summary>
public static class ScanPathPolicy
{
    public static bool IsAllowed(string? path, IEnumerable<string> allowedRoots, out string error)
    {
        error = string.Empty;
        if (string.IsNullOrWhiteSpace(path))
        {
            error = "ruta no indicada";
            return false;
        }
        if (path.IndexOfAny(new[] { '*', '?' }) >= 0)
        {
            error = "la ruta no puede contener comodines";
            return false;
        }

        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            error = "ruta no válida";
            return false;
        }

        var separator = Path.DirectorySeparatorChar;
        var dataRoot = Trim(AegisPaths.DataRoot);
        if (IsUnder(full, dataRoot))
        {
            error = "la ruta pertenece al directorio de estado de Aegis Guard";
            return false;
        }

        var forbidden = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        }.Where(p => !string.IsNullOrWhiteSpace(p)).Select(Trim).ToArray();
        if (forbidden.Any(root => IsUnder(full, root)))
        {
            error = "la ruta pertenece a una ubicación protegida del sistema";
            return false;
        }

        var normalizedRoots = (allowedRoots ?? Array.Empty<string>())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => { try { return Trim(Path.GetFullPath(p)); } catch { return string.Empty; } })
            .Where(p => p.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (!normalizedRoots.Any(root => IsUnder(full, root)))
        {
            error = "la ruta no está dentro de un directorio permitido";
            return false;
        }

        // Un junction/reparse point puede hacer que una ruta aparentemente
        // permitida termine en una ubicación protegida. Se rechaza cualquier
        // enlace en el segmento existente, incluido el propio fichero.
        var cursor = Path.GetPathRoot(full) ?? string.Empty;
        foreach (var segment in full.Substring(cursor.Length).Split(separator, StringSplitOptions.RemoveEmptyEntries))
        {
            cursor = Path.Combine(cursor, segment);
            if (!File.Exists(cursor) && !Directory.Exists(cursor)) break;
            FileSystemInfo item = Directory.Exists(cursor)
                ? new DirectoryInfo(cursor)
                : new FileInfo(cursor);
            if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                error = "la ruta contiene un enlace o reparse point";
                return false;
            }
        }

        return true;
    }

    public static IReadOnlyList<string> DefaultRoots()
    {
        var roots = new List<string>();
        var profile = ResolveProfile();
        if (!string.IsNullOrWhiteSpace(profile))
        {
            roots.AddRange(new[]
            {
                Path.Combine(profile, "Desktop"),
                Path.Combine(profile, "Documents"),
                Path.Combine(profile, "Downloads"),
                Path.Combine(profile, "AppData", "Local", "Temp")
            });
        }
        var configured = Environment.GetEnvironmentVariable("AEGIS_SCAN_ALLOWED_ROOTS");
        if (!string.IsNullOrWhiteSpace(configured))
            roots.AddRange(configured.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return roots.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string ResolveProfile()
    {
        if (OperatingSystem.IsWindows())
        {
            var sid = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
            if (!string.IsNullOrWhiteSpace(sid))
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                        $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
                    if (key?.GetValue("ProfileImagePath") is string path && !string.IsNullOrWhiteSpace(path))
                        return path;
                }
                catch { /* se usa el perfil del proceso */ }
            }
        }
        return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    }

    private static string Trim(string path) => path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static bool IsUnder(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(root)) return false;
        var comparison = StringComparison.OrdinalIgnoreCase;
        return path.Equals(root, comparison) ||
               path.StartsWith(root + Path.DirectorySeparatorChar, comparison);
    }
}

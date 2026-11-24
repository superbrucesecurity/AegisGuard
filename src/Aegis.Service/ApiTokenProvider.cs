using System.Security.Cryptography;
using System.Text;

namespace Aegis.Service;

/// <summary>
/// Token local de la API. El archivo se crea con ACL restringida; si ya
/// existía con permisos débiles se repara al cargarlo. Un token corrupto,
/// truncado o ilegible se sustituye por uno nuevo sin impedir el arranque,
/// conservando el archivo anterior como evidencia local.
/// </summary>
public sealed class ApiTokenProvider
{
    private const int TokenBytes = 32;
    private const string BearerPrefix = "Bearer ";
    private readonly string _path;
    private readonly object _gate = new();

    public ApiTokenProvider(string root)
    {
        _path = Path.Combine(root, "ui-token");
    }

    public string Token { get; private set; } = string.Empty;

    public void LoadOrCreate()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        lock (_gate)
        {
            if (File.Exists(_path))
            {
                try
                {
                    var existing = File.ReadAllText(_path).Trim();
                    if (IsWellFormed(existing))
                    {
                        Token = existing;
                        RepairAcl();
                        return;
                    }
                    PreserveInvalid(existing);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // No se puede leer: se genera una credencial nueva y se
                    // sobrescribe el archivo. El error no detiene el servicio.
                }
            }

            var generated = Convert.ToBase64String(RandomNumberGenerator.GetBytes(TokenBytes));
            WriteAtomic(generated);
            Token = generated;
            RepairAcl();
        }
    }

    /// <summary>
    /// Compara la cabecera completa sin ramas dependientes del valor del token.
    /// Se hashhea antes de comparar para no filtrar tampoco su longitud.
    /// </summary>
    public bool Matches(string? authorization)
    {
        var current = Token;
        if (string.IsNullOrEmpty(current)) return false;
        if (authorization is null || !authorization.StartsWith(BearerPrefix, StringComparison.Ordinal)) return false;

        var presented = authorization[BearerPrefix.Length..].Trim();
        var left = SHA256.HashData(Encoding.UTF8.GetBytes(presented));
        var right = SHA256.HashData(Encoding.UTF8.GetBytes(current));
        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    private static bool IsWellFormed(string value)
    {
        // 32 bytes -> 44 caracteres Base64 con un '=' final.
        if (value.Length != 44 || value[^1] != '=') return false;
        try { return Convert.FromBase64String(value).Length == TokenBytes; }
        catch (FormatException) { return false; }
    }

    private void PreserveInvalid(string content)
    {
        try
        {
            var preserved = Path.Combine(Path.GetDirectoryName(_path)!,
                $"ui-token.invalid-{Guid.NewGuid():N}");
            File.WriteAllText(preserved, content);
            if (OperatingSystem.IsWindows()) LocalFileAcl.Restrict(preserved);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Mejor esfuerzo: conservar evidencia no puede bloquear el arranque.
        }
    }

    private void WriteAtomic(string token)
    {
        var temp = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var bytes = Encoding.ASCII.GetBytes(token);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            if (OperatingSystem.IsWindows() && !LocalFileAcl.Restrict(temp))
                throw new IOException("No se pudieron restringir los permisos del token temporal.");
            File.Move(temp, _path, true);
        }
        finally
        {
            try { File.Delete(temp); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* mejor esfuerzo */ }
        }
    }

    private void RepairAcl()
    {
        if (OperatingSystem.IsWindows() && !LocalFileAcl.Restrict(_path))
            throw new IOException("No se pudieron restringir los permisos de ui-token.");
    }
}

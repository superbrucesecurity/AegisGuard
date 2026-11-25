using System.Text;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Registro local, con ACL restringida, de todos los intentos de operación
/// privilegiada, incluidos los rechazados. No sustituye al registro de eventos
/// del producto: es la evidencia de la superficie administrativa.
/// </summary>
public sealed class PrivilegedAuditLog
{
    private const long MaxBytes = 2 * 1024 * 1024;
    private readonly string _path;
    private readonly object _gate = new();

    public PrivilegedAuditLog(string root)
    {
        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "privileged-audit.jsonl");
        if (OperatingSystem.IsWindows() && File.Exists(_path)) LocalFileAcl.Restrict(_path);
    }

    public void Write(ClientIdentity identity, PrivilegedOperation operation, bool allowed, string detail)
    {
        var line = JsonSerializer.Serialize(new
        {
            utc = DateTimeOffset.UtcNow.ToString("O"),
            operation = operation.ToString(),
            allowed,
            detail,
            pid = identity.ProcessId,
            sid = identity.Sid,
            integrity = identity.IntegrityName,
            elevation = identity.Elevation.ToString(),
            administrator = identity.IsAdministrator,
            interactive = identity.IsInteractive
        }, JsonDefaults.Options);

        lock (_gate)
        {
            try
            {
                if (File.Exists(_path) && new FileInfo(_path).Length > MaxBytes)
                {
                    var rotated = _path + ".1";
                    if (File.Exists(rotated)) File.Delete(rotated);
                    File.Move(_path, rotated, true);
                    if (OperatingSystem.IsWindows() && File.Exists(rotated)) LocalFileAcl.Restrict(rotated);
                }
                using var stream = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.Read);
                var bytes = new UTF8Encoding(false).GetBytes(line + Environment.NewLine);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
                if (OperatingSystem.IsWindows()) LocalFileAcl.Restrict(_path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // La auditoría no puede impedir la operación ya autorizada, pero
                // el servicio registra el fallo en el registro de eventos de Windows.
            }
        }
    }
}

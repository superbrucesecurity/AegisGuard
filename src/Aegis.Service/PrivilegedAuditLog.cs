using System.Text;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Registro local, con ACL restringida, de todos los intentos de operación
/// privilegiada, incluidos los rechazados y los que fallan antes del parseo.
/// No sustituye al registro de eventos del producto: es la evidencia de la
/// superficie administrativa.
/// </summary>
public sealed class PrivilegedAuditLog
{
    private const long MaxBytes = 2 * 1024 * 1024;
    private readonly string _path;
    private readonly object _gate = new();
    private readonly ILogger? _logger;

    public PrivilegedAuditLog(string root, ILogger? logger = null)
    {
        Directory.CreateDirectory(root);
        _path = Path.Combine(root, "privileged-audit.jsonl");
        _logger = logger;
        if (OperatingSystem.IsWindows() && File.Exists(_path)) LocalFileAcl.Restrict(_path);
    }

    public void Write(ClientIdentity identity, PrivilegedOperation operation, bool allowed, string detail) =>
        WriteEntry(operation.ToString(), allowed, detail, identity.ProcessId, identity.Sid,
            identity.IntegrityName, identity.Elevation.ToString());

    public void WriteValidation(
        string operation,
        bool allowed,
        string detail,
        int? processId = null,
        string? sid = null,
        string? integrity = null,
        string? elevation = null) =>
        WriteEntry(operation, allowed, detail, processId, sid, integrity, elevation);

    private void WriteEntry(
        string operation,
        bool allowed,
        string detail,
        int? processId,
        string? sid,
        string? integrity,
        string? elevation)
    {
        var line = JsonSerializer.Serialize(new
        {
            utc = DateTimeOffset.UtcNow.ToString("O"),
            operation,
            allowed,
            detail,
            pid = processId,
            sid,
            integrity,
            elevation
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
                // el fallo debe quedar en el registro de eventos del producto.
                _logger?.LogError(ex, "No se pudo escribir la auditoría IPC en {Path}", _path);
            }
        }
    }
}

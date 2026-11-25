using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.UI;

/// <summary>
/// Puente entre la SPA y el servicio. Sustituye al token leído por JavaScript:
/// el navegador nunca recibe una credencial. Las operaciones sensibles se
/// ejecutan en un proceso elevado explícitamente autorizado por UAC.
/// </summary>
[ComVisible(true)]
public sealed class AegisBridge
{
    private const string ElevatedSwitch = "--aegis-admin-call";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<string> Invoke(string operation, string payloadJson)
    {
        if (string.IsNullOrWhiteSpace(operation)) return Failure("operación no indicada");
        if (!Enum.TryParse<UiOperation>(operation, ignoreCase: false, out var parsed))
            return Failure("operación desconocida");
        string request;
        JsonDocument document;
        try { document = JsonDocument.Parse(payloadJson); }
        catch (JsonException) { return Failure("payload no es JSON válido"); }
        using (document)
        {
            request = JsonSerializer.Serialize(new
            {
                operation = parsed.ToString(),
                payload = document.RootElement.Clone()
            }, JsonOptions);
        }

        try
        {
            if (IsElevated()) return await CallPipeAsync(request).ConfigureAwait(false);
            return await CallElevatedAsync(request).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return Failure(ex.Message);
        }
    }

    /// <summary>
    /// Procesa la invocación del proceso elevado. Devuelve true cuando la
    /// instancia actual es el helper y debe terminar sin abrir la interfaz.
    /// </summary>
    public static bool TryHandleElevatedCall(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (args.Length < 3 || !string.Equals(args[0], ElevatedSwitch, StringComparison.Ordinal))
            return false;
        var callerSid = args.Length > 3 ? args[3] : null;
        try
        {
            var request = Encoding.UTF8.GetString(Convert.FromBase64String(args[1]));
            var responsePath = args[2];
            var response = new AegisBridge().CallPipeAsync(request).GetAwaiter().GetResult();
            WriteRestricted(responsePath, response, callerSid);
        }
        catch (Exception ex)
        {
            exitCode = 1;
            try { WriteRestricted(args[2], Failure(ex.Message), callerSid); } catch { /* mejor esfuerzo */ }
        }
        return true;
    }

    private async Task<string> CallPipeAsync(string request)
    {
        var name = PipeNameForCurrentUser();
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await client.ConnectAsync(timeout.Token).ConfigureAwait(false);
        var bytes = Encoding.UTF8.GetBytes(request + "\n");
        await client.WriteAsync(bytes, timeout.Token).ConfigureAwait(false);
        await client.FlushAsync(timeout.Token).ConfigureAwait(false);

        using var reader = new StreamReader(client, Encoding.UTF8, false, 4096, leaveOpen: true);
        var line = await reader.ReadLineAsync().ConfigureAwait(false)
            ?? throw new IOException("el servicio no devolvió respuesta");
        using var document = JsonDocument.Parse(line);
        var root = document.RootElement;
        if (!root.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
        {
            var error = root.TryGetProperty("error", out var e) ? e.GetString() : "operación rechazada";
            throw new InvalidOperationException(error ?? "operación rechazada");
        }
        var result = root.TryGetProperty("result", out var r) ? r.GetRawText() : "{}";
        return result;
    }

    private static async Task<string> CallElevatedAsync(string request)
    {
        var responsePath = Path.Combine(Path.GetTempPath(),
            "aegis-" + Path.GetRandomFileName() + ".response");
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(request));
        // La respuesta debe poder leerla el proceso no elevado que la pidió,
        // aunque UAC haya solicitado credenciales de otra cuenta administradora.
        var callerSid = WindowsIdentity.GetCurrent().User?.Value;
        var start = new ProcessStartInfo
        {
            FileName = Environment.ProcessPath ?? "Aegis.UI.exe",
            Arguments = $"{ElevatedSwitch} {encoded} \"{responsePath}\" \"{callerSid}\"",
            UseShellExecute = true,
            Verb = "runas",
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("no se pudo iniciar el proceso elevado");
        await process.WaitForExitAsync().ConfigureAwait(false);
        if (process.ExitCode != 0 && !File.Exists(responsePath))
            throw new InvalidOperationException("el usuario rechazó la elevación o el proceso elevado falló");
        if (!File.Exists(responsePath))
            throw new InvalidOperationException("el proceso elevado no escribió la respuesta");
        var response = await File.ReadAllTextAsync(responsePath).ConfigureAwait(false);
        try { File.Delete(responsePath); } catch (IOException) { /* mejor esfuerzo */ }
        return response;
    }

    private static void WriteRestricted(string path, string content, string? callerSid)
    {
        var security = new FileSecurity();
        security.SetSecurityDescriptorSddlForm("D:");
        var elevatedSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("no se pudo obtener el SID del usuario");
        security.AddAccessRule(new FileSystemAccessRule(
            elevatedSid, FileSystemRights.FullControl, AccessControlType.Allow));
        if (!string.IsNullOrWhiteSpace(callerSid))
        {
            try
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(callerSid), FileSystemRights.Read, AccessControlType.Allow));
            }
            catch (ArgumentException)
            {
                // SID no válido: no se amplían permisos.
            }
        }
        // CreateNew impide reutilizar un archivo preexistente. El nombre es
        // aleatorio y %TEMP% ya hereda una ACL de usuario; se restringe antes
        // de escribir el contenido.
        using (new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { }
        new FileInfo(path).SetAccessControl(security);
        using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.None);
        var bytes = new UTF8Encoding(false).GetBytes(content);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(true);
    }

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string PipeNameForCurrentUser()
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new InvalidOperationException("no se pudo obtener el SID del usuario");
        return AegisIpcNames.PrivilegedPipe(sid);
    }

    private static string Failure(string error) =>
        JsonSerializer.Serialize(new { ok = false, error }, JsonOptions);

    private enum UiOperation
    {
        FirewallAddRule,
        FirewallRemoveRule,
        QuarantineRestore,
        QuarantinePurge,
        PolicyChange
    }
}

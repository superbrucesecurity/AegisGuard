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
/// el navegador nunca recibe una credencial. Las lecturas se autorizan por SID
/// del usuario instalado; las mutaciones exigen una elevación UAC real del
/// mismo usuario. La SPA no tiene acceso HTTP a datos del producto.
/// </summary>
[ComVisible(true)]
public sealed class AegisBridge
{
    private const string ElevatedSwitch = "--aegis-admin-call";
    private static readonly TimeSpan PipeTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ElevationTimeout = TimeSpan.FromMinutes(2);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<string> Invoke(string operation, string payloadJson)
    {
        if (string.IsNullOrWhiteSpace(operation)) return Failure("operación no indicada");
        if (!Enum.TryParse<PrivilegedOperation>(operation, ignoreCase: false, out var parsed))
            return Failure("operación desconocida");
        // El pipe existe para el SID fijado por la instalación. No se deriva
        // del usuario del proceso elevado: un UAC con otra cuenta no amplía
        // la autorización y debe fallar de forma explícita.
        string pipeSid;
        try { pipeSid = AegisIpcNames.RequireConfiguredAuthorizedSid(); }
        catch (InvalidOperationException ex) { return Failure(ex.Message); }

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
            if (parsed.RequiresElevation() && !IsElevated())
                return await CallElevatedAsync(request, pipeSid).ConfigureAwait(false);
            return await CallPipeAsync(request, pipeSid).ConfigureAwait(false);
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
            var pipeSid = args.Length > 4 ? args[4] : AegisIpcNames.RequireConfiguredAuthorizedSid();
            var request = Encoding.UTF8.GetString(Convert.FromBase64String(args[1]));
            var responsePath = args[2];
            var response = new AegisBridge().CallPipeAsync(request, pipeSid).GetAwaiter().GetResult();
            WriteRestricted(responsePath, response, callerSid);
        }
        catch (Exception ex)
        {
            exitCode = 1;
            try { WriteRestricted(args[2], Failure(ex.Message), callerSid); } catch { /* mejor esfuerzo */ }
        }
        return true;
    }

    private async Task<string> CallPipeAsync(string request, string? pipeSid)
    {
        var sid = string.IsNullOrWhiteSpace(pipeSid)
            ? AegisIpcNames.RequireConfiguredAuthorizedSid()
            : pipeSid;
        var name = AegisIpcNames.PrivilegedPipe(sid);
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var timeout = new CancellationTokenSource(PipeTimeout);
        await client.ConnectAsync(timeout.Token).ConfigureAwait(false);
        var bytes = Encoding.UTF8.GetBytes(request + "\n");
        await client.WriteAsync(bytes, timeout.Token).ConfigureAwait(false);
        await client.FlushAsync(timeout.Token).ConfigureAwait(false);

        using var reader = new StreamReader(client, Encoding.UTF8, false, 4096, leaveOpen: true);
        var line = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false)
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

    private static async Task<string> CallElevatedAsync(string request, string pipeSid)
    {
        var responseDir = Path.Combine(Path.GetTempPath(), "aegis-" + Path.GetRandomFileName());
        var responsePath = Path.Combine(responseDir, "response.json");
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(request));
        var callerSid = WindowsIdentity.GetCurrent().User?.Value;
        var start = new ProcessStartInfo
        {
            FileName = Environment.ProcessPath ?? "Aegis.UI.exe",
            UseShellExecute = true,
            Verb = "runas",
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };
        // ArgumentList evita que una comilla en %TEMP% rompa el entrecomillado
        // y permita alterar la ruta de respuesta o los SIDs.
        start.ArgumentList.Add(ElevatedSwitch);
        start.ArgumentList.Add(encoded);
        start.ArgumentList.Add(responsePath);
        start.ArgumentList.Add(callerSid ?? string.Empty);
        start.ArgumentList.Add(pipeSid);

        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("no se pudo iniciar el proceso elevado");
        using var timeout = new CancellationTokenSource(ElevationTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* mejor esfuerzo */ }
            throw new TimeoutException("la elevación administrativa tardó demasiado");
        }
        if (process.ExitCode != 0 && !File.Exists(responsePath))
            throw new InvalidOperationException("el usuario rechazó la elevación o el proceso elevado falló");
        if (!File.Exists(responsePath))
            throw new InvalidOperationException("el proceso elevado no escribió la respuesta");
        var response = await File.ReadAllTextAsync(responsePath).ConfigureAwait(false);
        try { Directory.Delete(responseDir, true); } catch (IOException) { /* mejor esfuerzo */ }
        return response;
    }

    private static void WriteRestricted(string path, string content, string? callerSid)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("la ruta de respuesta no tiene directorio");
        // El directorio nace vacío y se restringe ANTES de crear el fichero. Así
        // el archivo hereda una DACL que sólo permite al proceso elevado y al
        // llamante, sin ventana con la ACL de %TEMP%.
        var security = new DirectorySecurity();
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
                    new SecurityIdentifier(callerSid), FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            }
            catch (ArgumentException)
            {
                // SID no válido: no se amplían permisos.
            }
        }
        var directoryInfo = Directory.CreateDirectory(directory);
        directoryInfo.SetAccessControl(security);
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
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

    private static string Failure(string error) =>
        JsonSerializer.Serialize(new { ok = false, error }, JsonOptions);
}

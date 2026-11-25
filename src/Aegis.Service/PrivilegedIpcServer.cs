using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

public interface IPrivilegedOperationDispatcher
{
    Task<JsonElement> DispatchAsync(
        PrivilegedOperation operation,
        JsonElement payload,
        ClientIdentity identity,
        CancellationToken cancellationToken);
}

/// <summary>
/// Servidor IPC con ACL explícita, identificación del cliente y autorización
/// por operación. El token HTTP ya no concede acceso a operaciones sensibles.
/// </summary>
public sealed class PrivilegedIpcServer
{
    private readonly string _pipeName;
    private readonly IPrivilegedOperationDispatcher _dispatcher;
    private readonly PrivilegedAuditLog _audit;
    private readonly ILogger _logger;
    private readonly PipeSecurity _security;

    public PrivilegedIpcServer(
        string pipeName,
        IPrivilegedOperationDispatcher dispatcher,
        PrivilegedAuditLog audit,
        ILogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        _pipeName = pipeName;
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _security = BuildSecurity();
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var server = NamedPipeServerStreamAcl.Create(
                _pipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                4096,
                PrivilegedOperationPolicy.MaxResponseBytes,
                _security);

            try
            {
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                await HandleAsync(server, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (IOException ex)
            {
                _logger.LogWarning(ex, "Conexión IPC privilegiada interrumpida.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado en el servidor IPC privilegiado.");
            }
        }
    }

    private async Task HandleAsync(NamedPipeServerStream server, CancellationToken cancellationToken)
    {
        ClientIdentity? identity = null;
        PrivilegedOperation? auditedOperation = null;
        try
        {
            identity = NativeClientIdentity.FromPipe(server.SafePipeHandle);
            if (identity is null)
            {
                await WriteAsync(server, IpcResponse.Failure("no se pudo identificar al cliente")).ConfigureAwait(false);
                return;
            }

            var frame = await ReadFrameAsync(server, cancellationToken).ConfigureAwait(false);
            if (frame is null)
            {
                await WriteAsync(server, IpcResponse.Failure("solicitud vacía o demasiado grande")).ConfigureAwait(false);
                return;
            }

            IpcRequest? request;
            try { request = JsonSerializer.Deserialize<IpcRequest>(frame, JsonDefaults.Options); }
            catch (JsonException) { request = null; }
            var validationError = string.Empty;
            if (request is null || !request.TryValidate(out validationError))
            {
                if (request is null) validationError = "solicitud JSON no válida";
                await WriteAsync(server, IpcResponse.Failure(validationError)).ConfigureAwait(false);
                return;
            }

            var operation = request.Operation!.Value;
            auditedOperation = operation;
            var allowed = PrivilegedOperationPolicy.IsAllowed(identity, operation);
            var reason = allowed ? "autorizado" : PrivilegedOperationPolicy.DenialReason(identity, operation);
            _audit.Write(identity, operation, allowed, reason);
            _logger.LogInformation(
                "IPC privilegiado {Operation} pid={Pid} integridad={Integrity} elevación={Elevation}: {Reason}",
                operation, identity.ProcessId, identity.IntegrityName, identity.Elevation, reason);

            if (!allowed)
            {
                await WriteAsync(server, IpcResponse.Failure("acceso denegado: " + reason)).ConfigureAwait(false);
                return;
            }

            var result = await _dispatcher
                .DispatchAsync(operation, request.Payload, identity, cancellationToken)
                .ConfigureAwait(false);
            await WriteAsync(server, IpcResponse.Success(result)).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Apagado ordenado.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al atender una operación IPC privilegiada.");
            if (identity is not null && auditedOperation is not null)
                _audit.Write(identity, auditedOperation.Value, false, "error: " + ex.Message);
            try { await WriteAsync(server, IpcResponse.Failure("error interno")).ConfigureAwait(false); }
            catch (IOException) { /* el cliente ya se desconectó */ }
        }
    }

    private static async Task<string?> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        using var accumulated = new MemoryStream();
        while (accumulated.Length <= PrivilegedOperationPolicy.MaxRequestBytes)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            accumulated.Write(buffer, 0, read);
            var index = Array.IndexOf(buffer, (byte)'\n', 0, read);
            if (index >= 0)
            {
                var total = (int)accumulated.Length - read + index;
                accumulated.SetLength(total);
                break;
            }
        }
        if (accumulated.Length == 0 || accumulated.Length > PrivilegedOperationPolicy.MaxRequestBytes) return null;
        // StreamWriter de PowerShell añade BOM; no debe romper el parseo.
        return Encoding.UTF8.GetString(accumulated.ToArray()).Trim().TrimStart('\uFEFF').Trim();
    }

    private static async Task WriteAsync(Stream stream, IpcResponse response)
    {
        var json = JsonSerializer.Serialize(response, JsonDefaults.Options);
        var bytes = new UTF8Encoding(false).GetBytes(json + "\n");
        if (bytes.Length > PrivilegedOperationPolicy.MaxResponseBytes)
            bytes = new UTF8Encoding(false).GetBytes(
                JsonSerializer.Serialize(IpcResponse.Failure("respuesta demasiado grande"), JsonDefaults.Options) + "\n");
        await stream.WriteAsync(bytes, CancellationToken.None).ConfigureAwait(false);
        await stream.FlushAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private static PipeSecurity BuildSecurity()
    {
        var security = new PipeSecurity();
        // Se parte de una DACL vacía: sólo se conceden los accesos explícitos.
        security.SetSecurityDescriptorSddlForm("D:");
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        var uiSid = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        SecurityIdentifier interactive;
        if (!string.IsNullOrWhiteSpace(uiSid))
        {
            try { interactive = new SecurityIdentifier(uiSid); }
            catch (ArgumentException) { interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null); }
        }
        else interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);

        security.AddAccessRule(new PipeAccessRule(interactive, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return security;
    }
}

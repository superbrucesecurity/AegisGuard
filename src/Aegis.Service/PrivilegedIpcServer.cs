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
/// Servidor IPC local con ACL explícita, identificación real del cliente,
/// autorización por SID y por operación, timeouts por conexión y auditoría de
/// todos los intentos. Ninguna operación de la interfaz se sirve por HTTP.
/// </summary>
public sealed class PrivilegedIpcServer
{
    private const int MaxConcurrentClients = 4;
    private static readonly TimeSpan ClientTimeout = TimeSpan.FromSeconds(10);

    private readonly string _pipeName;
    private readonly string _authorizedSid;
    private readonly IPrivilegedOperationDispatcher _dispatcher;
    private readonly PrivilegedAuditLog _audit;
    private readonly ILogger _logger;
    private readonly PipeSecurity _security;
    private readonly SemaphoreSlim _slots = new(MaxConcurrentClients, MaxConcurrentClients);

    public PrivilegedIpcServer(
        string pipeName,
        IPrivilegedOperationDispatcher dispatcher,
        PrivilegedAuditLog audit,
        ILogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        _authorizedSid = AegisIpcNames.RequireConfiguredAuthorizedSid();
        if (!string.Equals(pipeName, AegisIpcNames.PrivilegedPipe(_authorizedSid), StringComparison.Ordinal))
            throw new InvalidOperationException("El nombre de la tubería no corresponde al SID autorizado por la instalación.");
        _pipeName = pipeName;
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _security = BuildSecurity(_authorizedSid);
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var loops = Enumerable.Range(0, MaxConcurrentClients)
            .Select(_ => AcceptLoopAsync(cancellationToken))
            .ToArray();
        await Task.WhenAll(loops).ConfigureAwait(false);
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = CreateServer();
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                await _slots.WaitAsync(cancellationToken).ConfigureAwait(false);
                var owned = server;
                server = null;
                _ = Task.Run(() => HandleClientAsync(owned, cancellationToken), cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                server?.Dispose();
                return;
            }
            catch (IOException ex)
            {
                server?.Dispose();
                _logger.LogWarning(ex, "Conexión IPC interrumpida antes de identificar al cliente.");
            }
            catch (Exception ex)
            {
                server?.Dispose();
                _logger.LogError(ex, "Error inesperado aceptando una conexión IPC.");
            }
        }
    }

    private NamedPipeServerStream CreateServer() => NamedPipeServerStreamAcl.Create(
        _pipeName,
        PipeDirection.InOut,
        MaxConcurrentClients,
        PipeTransmissionMode.Byte,
        PipeOptions.Asynchronous | PipeOptions.WriteThrough,
        4096,
        PrivilegedOperationPolicy.MaxResponseBytes,
        _security);

    private async Task HandleClientAsync(NamedPipeServerStream server, CancellationToken shutdownToken)
    {
        await using (server.ConfigureAwait(false))
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(shutdownToken);
            timeout.CancelAfter(ClientTimeout);
            try
            {
                await HandleAsync(server, timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && !shutdownToken.IsCancellationRequested)
            {
                _audit.WriteValidation("timeout", false, "el cliente excedió el tiempo de la conexión");
                try { await WriteAsync(server, IpcResponse.Failure("tiempo de conexión agotado"), CancellationToken.None); }
                catch (IOException) { /* el cliente ya se desconectó */ }
            }
            catch (OperationCanceledException) when (shutdownToken.IsCancellationRequested)
            {
                // Apagado ordenado.
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al atender una conexión IPC.");
                _audit.WriteValidation("error", false, ex.Message);
            }
            finally
            {
                _slots.Release();
            }
        }
    }

    private async Task HandleAsync(NamedPipeServerStream server, CancellationToken cancellationToken)
    {
        ClientIdentity? identity = null;
        try
        {
            identity = NativeClientIdentity.FromPipe(server.SafePipeHandle);
            if (identity is null)
            {
                _audit.WriteValidation("handshake", false, "no se pudo identificar al cliente");
                await WriteAsync(server, IpcResponse.Failure("no se pudo identificar al cliente"), cancellationToken).ConfigureAwait(false);
                return;
            }

            if (!PrivilegedOperationPolicy.IsAuthorizedSid(identity, _authorizedSid))
            {
                _audit.WriteValidation("authorization", false,
                    "el SID del cliente no es el usuario autorizado por la instalación",
                    identity.ProcessId, identity.Sid, identity.IntegrityName, identity.Elevation.ToString());
                await WriteAsync(server, IpcResponse.Failure("acceso denegado: identidad no autorizada"), cancellationToken).ConfigureAwait(false);
                return;
            }

            var frame = await ReadFrameAsync(server, cancellationToken).ConfigureAwait(false);
            if (frame is null)
            {
                _audit.WriteValidation("validation", false, "solicitud vacía o demasiado grande",
                    identity.ProcessId, identity.Sid, identity.IntegrityName, identity.Elevation.ToString());
                await WriteAsync(server, IpcResponse.Failure("solicitud vacía o demasiado grande"), cancellationToken).ConfigureAwait(false);
                return;
            }

            IpcRequest? request;
            try { request = JsonSerializer.Deserialize<IpcRequest>(frame, JsonDefaults.Options); }
            catch (JsonException) { request = null; }
            string requestError = string.Empty;
            var validRequest = request is not null && request.TryValidate(out requestError);
            string validationError;
            if (validRequest)
            {
                validationError = string.Empty;
            }
            else
            {
                validationError = request is null ? "solicitud JSON no válida" : requestError;
                _audit.WriteValidation("validation", false, validationError,
                    identity.ProcessId, identity.Sid, identity.IntegrityName, identity.Elevation.ToString());
                await WriteAsync(server, IpcResponse.Failure(validationError), cancellationToken).ConfigureAwait(false);
                return;
            }

            var operation = request!.Operation!.Value;
            var allowed = PrivilegedOperationPolicy.IsAllowed(identity, operation);
            var reason = allowed ? "autorizado" : PrivilegedOperationPolicy.DenialReason(identity, operation);
            _audit.Write(identity, operation, allowed, reason);
            _logger.LogInformation(
                "IPC {Operation} pid={Pid} integridad={Integrity} elevación={Elevation}: {Reason}",
                operation, identity.ProcessId, identity.IntegrityName, identity.Elevation, reason);

            if (!allowed)
            {
                await WriteAsync(server, IpcResponse.Failure("acceso denegado: " + reason), cancellationToken).ConfigureAwait(false);
                return;
            }

            var result = await _dispatcher
                .DispatchAsync(operation, request.Payload, identity, cancellationToken)
                .ConfigureAwait(false);
            await WriteAsync(server, IpcResponse.Success(result), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            // Mensajes controlados por el producto: permiten explicar al usuario
            // por qué se rechazó una ruta o un elemento sin revelar el estado.
            _audit.WriteValidation("validacion", false, ex.Message,
                identity?.ProcessId, identity?.Sid, identity?.IntegrityName, identity?.Elevation.ToString());
            try { await WriteAsync(server, IpcResponse.Failure(ex.Message), CancellationToken.None).ConfigureAwait(false); }
            catch (IOException) { /* el cliente ya se desconectó */ }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al ejecutar una operación IPC.");
            if (identity is not null)
                _audit.WriteValidation("error", false, ex.Message,
                    identity.ProcessId, identity.Sid, identity.IntegrityName, identity.Elevation.ToString());
            try { await WriteAsync(server, IpcResponse.Failure("error interno"), CancellationToken.None).ConfigureAwait(false); }
            catch (IOException) { /* el cliente ya se desconectó */ }
        }
    }

    private static async Task<string?> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        using var accumulated = new MemoryStream();
        while (accumulated.Length <= PrivilegedOperationPolicy.MaxRequestBytes)
        {
            cancellationToken.ThrowIfCancellationRequested();
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

    private static async Task WriteAsync(Stream stream, IpcResponse response, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(response, JsonDefaults.Options);
        var bytes = new UTF8Encoding(false).GetBytes(json + "\n");
        if (bytes.Length > PrivilegedOperationPolicy.MaxResponseBytes)
            bytes = new UTF8Encoding(false).GetBytes(
                JsonSerializer.Serialize(IpcResponse.Failure("respuesta demasiado grande"), JsonDefaults.Options) + "\n");
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sólo SYSTEM y el usuario autorizado por la instalación pueden abrir la
    /// tubería. No se concede acceso a Interactive ni a cualquier administrador:
    /// la elevación con otra cuenta no amplía la autorización.
    /// </summary>
    public static PipeSecurity BuildSecurity(string authorizedSid)
    {
        var security = new PipeSecurity();
        security.SetSecurityDescriptorSddlForm("D:");
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(authorizedSid),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        return security;
    }
}

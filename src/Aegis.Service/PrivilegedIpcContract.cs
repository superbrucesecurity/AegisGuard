using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Resuelve el SID autorizado de la misma forma en que lo hace el instalador.
/// En el servicio SCM ese SID se registra como variable de entorno; al ejecutar
/// en consola se usa el usuario actual.
/// </summary>
public static class PrivilegedIpcEndpoints
{
    public static string PipeNameForSid(string sid) => AegisIpcNames.PrivilegedPipe(sid);

    public static string PipeNameForCurrentUser()
    {
        var sid = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        if (string.IsNullOrWhiteSpace(sid) && OperatingSystem.IsWindows())
            sid = WindowsIdentity.GetCurrent().User?.Value;
        return AegisIpcNames.PrivilegedPipe(string.IsNullOrWhiteSpace(sid) ? "aegis-console" : sid);
    }
}

/// <summary>
/// Operaciones que sólo pueden ejecutarse a través de IPC privilegiado.
/// Ninguna de ellas está disponible en la API HTTP de la interfaz.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<PrivilegedOperation>))]
public enum PrivilegedOperation
{
    FirewallAddRule,
    FirewallRemoveRule,
    QuarantineRestore,
    QuarantinePurge,
    PolicyChange
}

/// <summary>
/// Valores de TOKEN_ELEVATION_TYPE de winnt.h: 1=Default, 2=Full, 3=Limited.
/// </summary>
public enum TokenElevationType
{
    Default = 1,
    Full = 2,
    Limited = 3
}

public enum ClientClearance
{
    Standard = 0,
    Elevated = 1
}

/// <summary>
/// Identidad verificada del proceso que abre la tubería. No se obtiene de un
/// valor enviado por el cliente: se lee del token del proceso mediante APIs
/// de Windows y se valida en el servidor.
/// </summary>
public sealed record ClientIdentity(
    int ProcessId,
    string Sid,
    int IntegrityRid,
    TokenElevationType Elevation,
    bool IsAdministrator,
    bool IsInteractive)
{
    public ClientClearance Clearance =>
        Elevation == TokenElevationType.Full &&
        IntegrityRid >= NativeClientIdentity.HighIntegrityRid &&
        IsAdministrator
            ? ClientClearance.Elevated
            : ClientClearance.Standard;

    public string IntegrityName => IntegrityRid switch
    {
        >= NativeClientIdentity.SystemIntegrityRid => "system",
        >= NativeClientIdentity.HighIntegrityRid => "high",
        >= NativeClientIdentity.MediumIntegrityRid => "medium",
        >= NativeClientIdentity.LowIntegrityRid => "low",
        _ => "untrusted"
    };
}

/// <summary>
/// Política de autorización por operación. Estas reglas son independientes de
/// Windows y se comprueban con pruebas unitarias.
/// </summary>
public static class PrivilegedOperationPolicy
{
    public const int MaxRequestBytes = 64 * 1024;
    public const int MaxResponseBytes = 256 * 1024;

    public static ClientClearance Required(PrivilegedOperation operation) => operation switch
    {
        PrivilegedOperation.FirewallAddRule => ClientClearance.Elevated,
        PrivilegedOperation.FirewallRemoveRule => ClientClearance.Elevated,
        PrivilegedOperation.QuarantineRestore => ClientClearance.Elevated,
        PrivilegedOperation.QuarantinePurge => ClientClearance.Elevated,
        PrivilegedOperation.PolicyChange => ClientClearance.Elevated,
        _ => ClientClearance.Elevated
    };

    public static bool IsAllowed(ClientIdentity identity, PrivilegedOperation operation)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!Enum.IsDefined(operation) || string.IsNullOrWhiteSpace(identity.Sid)) return false;
        if (!identity.IsInteractive) return false;
        if (identity.ProcessId <= 0) return false;

        var required = Required(operation);
        if (required == ClientClearance.Standard)
            return identity.IntegrityRid >= NativeClientIdentity.MediumIntegrityRid;

        return identity.Clearance == ClientClearance.Elevated;
    }

    public static string DenialReason(ClientIdentity identity, PrivilegedOperation operation)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (!identity.IsInteractive) return "el cliente no pertenece a la sesión interactiva autorizada";
        if (identity.Elevation == TokenElevationType.Limited)
            return "el cliente está elevado de forma incompleta (token limitado)";
        if (identity.Clearance != ClientClearance.Elevated)
            return $"se requiere consentimiento administrativo real (integridad {identity.IntegrityName})";
        return $"operación {operation} no autorizada para esta identidad";
    }
}

public sealed class IpcRequest
{
    [JsonPropertyName("operation")]
    public PrivilegedOperation? Operation { get; set; }

    [JsonPropertyName("payload")]
    public JsonElement Payload { get; set; }

    public bool TryValidate(out string error)
    {
        if (Operation is null || !Enum.IsDefined(Operation.Value))
        {
            error = "operación desconocida";
            return false;
        }
        if (Payload.ValueKind is not (JsonValueKind.Object or JsonValueKind.Undefined or JsonValueKind.Null))
        {
            error = "payload debe ser un objeto JSON";
            return false;
        }
        error = string.Empty;
        return true;
    }
}

public sealed class IpcResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("result")]
    public JsonElement Result { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    public static IpcResponse Success(JsonElement result) => new() { Ok = true, Result = result };

    public static IpcResponse Failure(string error) => new()
    {
        Ok = false,
        Result = JsonSerializer.SerializeToElement(new { }, JsonDefaults.Options),
        Error = error
    };
}

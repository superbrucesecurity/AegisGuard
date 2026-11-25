using System.Text.Json.Serialization;

namespace Aegis.Core;

/// <summary>
/// Operaciones atendidas por el canal IPC local. No todas requieren elevación:
/// las lecturas y los análisis se autorizan por SID del usuario instalado, y
/// las mutaciones exigen además un token administrativo completo.
/// Es la única definición compartida por servicio, UI y pruebas; la SPA debe
/// usar exactamente estos nombres en sus rutas internas.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<PrivilegedOperation>))]
public enum PrivilegedOperation
{
    Health,
    Status,
    Events,
    Threats,
    QuarantineList,
    FirewallRules,
    FirewallStats,
    FirewallLearned,
    SettingsGet,
    ScanPath,
    SelftestEicar,
    FirewallAddRule,
    FirewallRemoveRule,
    QuarantineRestore,
    QuarantinePurge,
    PolicyChange
}

/// <summary>
/// Política mínima compartida con la UI: decide si debe pedirse consentimiento
/// UAC antes de enviar la solicitud por la tubería.
/// </summary>
public static class PrivilegedOperationExtensions
{
    public static bool RequiresElevation(this PrivilegedOperation operation) => operation is
        PrivilegedOperation.FirewallAddRule or
        PrivilegedOperation.FirewallRemoveRule or
        PrivilegedOperation.QuarantineRestore or
        PrivilegedOperation.QuarantinePurge or
        PrivilegedOperation.PolicyChange;
}

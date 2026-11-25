using System.Text.Json.Serialization;

namespace Aegis.Core;

/// <summary>
/// Operaciones que sólo pueden ejecutarse a través del canal privilegiado.
/// Es la única definición compartida por servicio, UI y pruebas; la SPA debe
/// usar exactamente estos nombres en sus rutas internas.
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

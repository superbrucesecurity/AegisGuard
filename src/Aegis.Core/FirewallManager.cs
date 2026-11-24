using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace Aegis.Core;

[SupportedOSPlatform("windows")]

/// <summary>
/// Gestiona reglas del firewall de Windows (WFP) mediante la API COM
/// HNetCfg.FwPolicy2. No instala un controlador en kernel: usa el motor WFP
/// del sistema, que es la capa de filtrado soportada y firmada por Microsoft.
/// </summary>
public sealed class FirewallManager
{
    private const int NetFwActionBlock = 0;
    private const int NetFwActionAllow = 1;
    private const int NetFwRuleDirIn = 1;
    private const int NetFwRuleDirOut = 2;
    private const int NetFwProtoAny = 256;
    private const int NetFwProfileAll = 0x7FFFFFFF;
    private const string Prefix = "AEGIS Guard";
    private readonly object _gate = new();

    public string ProductPrefix => Prefix;

    public bool IsAvailable()
    {
        object? policy = null;
        try
        {
            policy = CreatePolicy();
            return true;
        }
        catch (COMException) { return false; }
        catch (InvalidOperationException) { return false; }
        finally { Release(policy); }
    }

    public string BuildRuleName(FirewallRuleSpec spec)
    {
        var target = spec.ApplicationPath is null ? "any" : Path.GetFileName(spec.ApplicationPath);
        var remote = spec.RemoteAddresses is null ? "any" : spec.RemoteAddresses.Replace('/', '_').Replace(',', '-');
        var port = spec.RemotePort?.ToString() ?? "any";
        var direction = spec.Inbound ? "IN" : "OUT";
        var action = spec.Block ? "BLOCK" : "ALLOW";
        var raw = $"{ProductPrefix} - {action} - {direction} - {target} - {remote} - {port}";
        if (raw.Length <= 250) return raw;
        // Conservar un sufijo único evita que dos reglas largas colisionen.
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)))[..8].ToLowerInvariant();
        return raw[..(250 - hash.Length - 1)] + "-" + hash;
    }

    public bool AddRule(FirewallRuleSpec spec)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(spec.Name);
        if (!IsOwnRule(spec.Name)) return false;
        if (spec.RemotePort is < 1 or > 65535) return false;

        object? policy = null;
        object? rule = null;
        lock (_gate)
        {
            try
            {
                policy = CreatePolicy();
                dynamic rules = ((dynamic)policy!).Rules;
                string? existingName = null;
                foreach (dynamic existing in rules)
                {
                    if (string.Equals((string)existing.Name, spec.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        existingName = (string)existing.Name;
                        break;
                    }
                }
                // Actualizar todos los criterios: reactivar una regla antigua
                // con otra IP/puerto dejaría un bloqueo incorrecto.
                if (existingName is not null) rules.Remove(existingName);

                rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule", true)!)!;
                dynamic fwRule = rule!;
                fwRule.Name = spec.Name;
                fwRule.Description = spec.Description;
                fwRule.Action = spec.Block ? NetFwActionBlock : NetFwActionAllow;
                fwRule.Direction = spec.Inbound ? NetFwRuleDirIn : NetFwRuleDirOut;
                fwRule.Protocol = spec.Protocol == 0 ? NetFwProtoAny : spec.Protocol;
                fwRule.Profiles = NetFwProfileAll;
                fwRule.Enabled = true;
                if (!string.IsNullOrWhiteSpace(spec.ApplicationPath)) fwRule.ApplicationName = spec.ApplicationPath;
                if (!string.IsNullOrWhiteSpace(spec.RemoteAddresses)) fwRule.RemoteAddresses = spec.RemoteAddresses;
                if (spec.RemotePort.HasValue) fwRule.RemotePorts = spec.RemotePort.Value.ToString();
                rules.Add(rule);
                return true;
            }
            finally
            {
                Release(rule);
                Release(policy);
            }
        }
    }

    public bool RemoveRule(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || !IsOwnRule(name)) return false;
        object? policy = null;
        lock (_gate)
        {
            try
            {
                policy = CreatePolicy();
                dynamic rules = ((dynamic)policy!).Rules;
                string? target = null;
                foreach (dynamic existing in rules)
                {
                    if (string.Equals((string)existing.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        target = (string)existing.Name;
                        break;
                    }
                }
                if (target is null) return false;
                // Salir del enumerador antes de modificar la colección COM.
                rules.Remove(target);
                return true;
            }
            finally { Release(policy); }
        }
    }

    /// <summary>
    /// Acepta los formatos "N" (sin guiones, usado por ThreatRecord.Id) y "D"
    /// (con guiones, usado por Guid.ToString). Rechaza cualquier otro texto.
    /// </summary>
    public static bool TryParseThreatId(string? threatId, out Guid guid)
    {
        if (!string.IsNullOrWhiteSpace(threatId) &&
            (Guid.TryParseExact(threatId, "N", out guid) || Guid.TryParseExact(threatId, "D", out guid)))
            return true;
        guid = Guid.Empty;
        return false;
    }

    /// <summary>
    /// Comprueba si una descripción pertenece a una regla automática del
    /// hallazgo. Se aceptan ambos formatos del GUID para no dejar reglas
    /// huérfanas al restaurar o purgar una amenaza.
    /// </summary>
    public static bool IsThreatRuleDescription(string? description, string? threatId) =>
        TryParseThreatId(threatId, out var guid) &&
        (description?.StartsWith($"{Prefix} - {guid:N} -", StringComparison.OrdinalIgnoreCase) == true ||
         description?.StartsWith($"{Prefix} - {guid:D} -", StringComparison.OrdinalIgnoreCase) == true);

    /// <summary>
    /// Clasifica una descripción como regla automática sin conocer el GUID del
    /// hallazgo, para poder contar automáticas y manuales en el panel.
    /// </summary>
    public static bool IsAutomaticThreatDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description)) return false;
        var marker = $"{Prefix} - ";
        if (!description.StartsWith(marker, StringComparison.OrdinalIgnoreCase)) return false;
        var rest = description[marker.Length..];
        var end = rest.IndexOf(" - ", StringComparison.Ordinal);
        if (end <= 0) return false;
        return TryParseThreatId(rest[..end], out _);
    }

    /// <summary>
    /// Elimina las reglas creadas automáticamente para un hallazgo. La Description
    /// incluye el ThreatId, lo que permite no tocar reglas de otros productos ni
    /// reglas creadas manualmente por el usuario.
    /// </summary>
    public int RemoveRulesForThreat(string threatId)
    {
        if (!TryParseThreatId(threatId, out _)) return 0;
        object? policy = null;
        lock (_gate)
        {
            try
            {
                policy = CreatePolicy();
                dynamic rules = ((dynamic)policy!).Rules;
                var names = new List<string>();
                foreach (dynamic rule in rules)
                {
                    try
                    {
                        var description = (string?)rule.Description ?? string.Empty;
                        if (IsThreatRuleDescription(description, threatId))
                            names.Add((string)rule.Name);
                    }
                    finally { Release(rule); }
                }
                foreach (var name in names) rules.Remove(name);
                return names.Count;
            }
            catch (COMException) { return 0; }
            catch (InvalidOperationException) { return 0; }
            finally { Release(policy); }
        }
    }

    public List<FirewallRuleSummary> ListRules()
    {
        object? policy = null;
        lock (_gate)
        {
            try
            {
                policy = CreatePolicy();
                var result = new List<FirewallRuleSummary>();
                foreach (dynamic rule in ((dynamic)policy!).Rules)
                {
                    try
                    {
                        var name = (string)rule.Name;
                        if (!IsOwnRule(name)) continue;
                        var description = (string?)rule.Description ?? string.Empty;
                        result.Add(new FirewallRuleSummary
                        {
                            Name = name,
                            Automatic = IsAutomaticThreatDescription(description)
                        });
                    }
                    finally { Release(rule); }
                }
                return result;
            }
            finally { Release(policy); }
        }
    }

    public List<string> ListRuleNames() => ListRules().Select(x => x.Name).ToList();

    private bool IsOwnRule(string name)
    {
        if (!name.StartsWith(ProductPrefix, StringComparison.OrdinalIgnoreCase)) return false;
        if (name.Length == ProductPrefix.Length) return true;
        // "AEGIS GuardEvil" no es una regla propia.
        return !char.IsLetterOrDigit(name[ProductPrefix.Length]);
    }

    private static object CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)
                   ?? throw new InvalidOperationException("El firewall de Windows no está disponible en este equipo.");
        return Activator.CreateInstance(type)
               ?? throw new InvalidOperationException("No se pudo abrir HNetCfg.FwPolicy2; se requieren privilegios de administrador.");
    }

    private static void Release(object? com)
    {
        if (com is not null && Marshal.IsComObject(com))
            Marshal.FinalReleaseComObject(com);
    }
}

using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Ejecuta las operaciones sensibles contra los mismos servicios reales que
/// usaba antes la API HTTP. No hay credenciales transportadas por la tubería:
/// la autorización ya fue comprobada desde el token del proceso cliente.
/// </summary>
public sealed class PrivilegedIpcDispatcher : IPrivilegedOperationDispatcher
{
    private readonly ConfigStore _config;
    private readonly RuntimeState _state;
    private readonly EventStore _store;
    private readonly QuarantineManager _quarantine;
    private readonly FirewallManager _firewall;

    public PrivilegedIpcDispatcher(
        ConfigStore config,
        RuntimeState state,
        EventStore store,
        QuarantineManager quarantine,
        FirewallManager firewall)
    {
        _config = config;
        _state = state;
        _store = store;
        _quarantine = quarantine;
        _firewall = firewall;
    }

    public async Task<JsonElement> DispatchAsync(
        PrivilegedOperation operation,
        JsonElement payload,
        ClientIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        return operation switch
        {
            PrivilegedOperation.FirewallAddRule => AddFirewallRule(payload),
            PrivilegedOperation.FirewallRemoveRule => RemoveFirewallRule(payload),
            PrivilegedOperation.QuarantineRestore => await RestoreAsync(payload).ConfigureAwait(false),
            PrivilegedOperation.QuarantinePurge => await PurgeAsync(payload).ConfigureAwait(false),
            PrivilegedOperation.PolicyChange => ChangePolicy(payload),
            _ => throw new InvalidOperationException("operación no soportada")
        };
    }

    private JsonElement AddFirewallRule(JsonElement payload)
    {
        var spec = Read<FirewallRuleSpec>(payload, "spec");
        EnsureBlockOnly(spec);
        spec.Name = spec.Name.StartsWith(_firewall.ProductPrefix, StringComparison.OrdinalIgnoreCase)
            ? spec.Name
            : _firewall.BuildRuleName(spec);
        if (!_firewall.AddRule(spec))
            throw new InvalidOperationException("no se pudo crear la regla");
        return JsonSerializer.SerializeToElement(new { name = spec.Name }, JsonDefaults.Options);
    }

    /// <summary>
    /// El producto sólo crea reglas de bloqueo: una regla Allow debilitaría la
    /// defensa local incluso si la pidiera un cliente elevado. Se comprueba
    /// antes de tocar el firewall y es verificable sin COM.
    /// </summary>
    public static void EnsureBlockOnly(FirewallRuleSpec spec)
    {
        ArgumentNullException.ThrowIfNull(spec);
        if (!spec.Block)
            throw new ArgumentException("Aegis Guard no crea reglas Allow: sólo bloquea tráfico");
        if (spec.RemotePort is < 1 or > 65535)
            throw new ArgumentException("puerto remoto fuera de rango");
        if (spec.Protocol is < 0 or > 256)
            throw new ArgumentException("protocolo fuera de rango");
    }

    private JsonElement RemoveFirewallRule(JsonElement payload)
    {
        var name = ReadString(payload, "name");
        if (!_firewall.RemoveRule(name))
            throw new InvalidOperationException("no se pudo eliminar la regla");
        return JsonSerializer.SerializeToElement(new { removed = true }, JsonDefaults.Options);
    }

    private async Task<JsonElement> RestoreAsync(JsonElement payload)
    {
        var id = ReadString(payload, "id");
        var item = await _quarantine.GetAsync(id).ConfigureAwait(false);
        if (item is null || !await _quarantine.RestoreAsync(id).ConfigureAwait(false))
            throw new InvalidOperationException("elemento no restaurable");
        await _store.MarkRemediatedAsync(item.ThreatId, "restaurado por administrador").ConfigureAwait(false);
        _firewall.RemoveRulesForThreat(item.ThreatId);
        return JsonSerializer.SerializeToElement(new { restored = true }, JsonDefaults.Options);
    }

    private async Task<JsonElement> PurgeAsync(JsonElement payload)
    {
        var id = ReadString(payload, "id");
        var item = await _quarantine.GetAsync(id).ConfigureAwait(false);
        if (item is null || !await _quarantine.PurgeAsync(id).ConfigureAwait(false))
            throw new InvalidOperationException("elemento no purgable");
        await _store.MarkRemediatedAsync(item.ThreatId, "purgado por administrador").ConfigureAwait(false);
        _firewall.RemoveRulesForThreat(item.ThreatId);
        return JsonSerializer.SerializeToElement(new { purged = true }, JsonDefaults.Options);
    }

    private JsonElement ChangePolicy(JsonElement payload)
    {
        var policy = Read<PolicySettings>(payload, "policy");
        policy.Validate();
        _config.SavePolicy(policy);
        _state.UpdatePolicy(_config.Policy);
        _store.SetMaxEvents(policy.MaxEvents);
        return JsonSerializer.SerializeToElement(_state.GetPolicy(), JsonDefaults.Options);
    }

    private static T Read<T>(JsonElement payload, string property)
    {
        if (payload.ValueKind != JsonValueKind.Object || !payload.TryGetProperty(property, out var value))
            throw new ArgumentException($"falta {property}");
        try
        {
            return value.Deserialize<T>(JsonDefaults.Options)
                ?? throw new ArgumentException($"{property} no puede ser nulo");
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"{property} no es válido: {ex.Message}");
        }
    }

    private static string ReadString(JsonElement payload, string property)
    {
        if (payload.ValueKind != JsonValueKind.Object ||
            !payload.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.String)
            throw new ArgumentException($"falta {property}");
        var text = value.GetString();
        if (string.IsNullOrWhiteSpace(text)) throw new ArgumentException($"{property} está vacío");
        return text;
    }
}

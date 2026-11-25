using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Ejecuta las operaciones del canal IPC contra los mismos servicios reales
/// que antes se consultaban por HTTP. No hay credenciales transportadas por la
/// tubería: la autorización ya fue comprobada desde el token del proceso cliente.
/// La API HTTP queda reducida a contenido estático y comprobación de disponibilidad.
/// </summary>
public sealed class PrivilegedIpcDispatcher : IPrivilegedOperationDispatcher
{
    private const int MaxConcurrentScans = 2;
    private readonly ConfigStore _config;
    private readonly RuntimeState _state;
    private readonly EventStore _store;
    private readonly QuarantineManager _quarantine;
    private readonly FirewallManager _firewall;
    private readonly DetectionPipeline _pipeline;
    private readonly SemaphoreSlim _scanGate = new(MaxConcurrentScans, MaxConcurrentScans);

    public PrivilegedIpcDispatcher(
        ConfigStore config,
        RuntimeState state,
        EventStore store,
        QuarantineManager quarantine,
        FirewallManager firewall,
        DetectionPipeline pipeline)
    {
        _config = config;
        _state = state;
        _store = store;
        _quarantine = quarantine;
        _firewall = firewall;
        _pipeline = pipeline;
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
            PrivilegedOperation.Health => Health(),
            PrivilegedOperation.Status => Serialize(_state.Snapshot(_firewall.IsAvailable())),
            PrivilegedOperation.Events => Events(payload),
            PrivilegedOperation.Threats => Threats(payload),
            PrivilegedOperation.QuarantineList => Serialize(await _quarantine.ListAsync().ConfigureAwait(false)),
            PrivilegedOperation.FirewallRules => Serialize(_firewall.ListRuleNames()),
            PrivilegedOperation.FirewallStats => FirewallStats(),
            PrivilegedOperation.FirewallLearned => Serialize(_pipeline.LearnedConnections),
            PrivilegedOperation.SettingsGet => Serialize(_state.GetPolicy()),
            PrivilegedOperation.ScanPath => await ScanAsync(payload, cancellationToken).ConfigureAwait(false),
            PrivilegedOperation.SelftestEicar =>
                Serialize(await _pipeline.SelfTestEicarAsync(cancellationToken).ConfigureAwait(false)),
            PrivilegedOperation.FirewallAddRule => AddFirewallRule(payload),
            PrivilegedOperation.FirewallRemoveRule => RemoveFirewallRule(payload),
            PrivilegedOperation.QuarantineRestore => await RestoreAsync(payload).ConfigureAwait(false),
            PrivilegedOperation.QuarantinePurge => await PurgeAsync(payload).ConfigureAwait(false),
            PrivilegedOperation.PolicyChange => ChangePolicy(payload),
            _ => throw new InvalidOperationException("operación no soportada")
        };
    }

    private static JsonElement Health() => Serialize(new
    {
        ok = true,
        version = typeof(PrivilegedIpcDispatcher).Assembly.GetName().Version?.ToString(3) ?? "0.0.0"
    });

    private JsonElement Events(JsonElement payload)
    {
        var limit = Math.Clamp(ReadInt(payload, "limit", 100), 1, 1000);
        var skip = Math.Max(0, ReadInt(payload, "skip", 0));
        var severity = ReadOptionalString(payload, "severity");
        var verdict = ReadOptionalString(payload, "verdict");
        var threats = _store.Threats;
        var items = _store.Observations
            .Select(o =>
            {
                var node = JsonSerializer.SerializeToNode(o, JsonDefaults.Options)!.AsObject();
                var decision = threats.FirstOrDefault(t =>
                    string.Equals(t.Decision.ObservationId, o.Id, StringComparison.Ordinal))?.Decision;
                node["decision"] = decision is null
                    ? null
                    : JsonSerializer.SerializeToNode(decision, JsonDefaults.Options);
                return (node, decision);
            })
            .Where(x => string.IsNullOrWhiteSpace(severity) ||
                        string.Equals(x.decision?.Severity.ToString(), severity, StringComparison.OrdinalIgnoreCase))
            .Where(x => string.IsNullOrWhiteSpace(verdict) ||
                        string.Equals(x.decision?.Verdict.ToString(), verdict, StringComparison.OrdinalIgnoreCase))
            .Reverse()
            .Skip(skip)
            .Take(limit)
            .Select(x => x.node)
            .ToList();
        return Serialize(items);
    }

    private JsonElement Threats(JsonElement payload)
    {
        var limit = Math.Clamp(ReadInt(payload, "limit", 100), 1, 1000);
        var skip = Math.Max(0, ReadInt(payload, "skip", 0));
        var severity = ReadOptionalString(payload, "severity");
        var items = _store.Threats
            .Where(x => x.Decision.Verdict != Verdict.Allow)
            .Where(x => string.IsNullOrWhiteSpace(severity) ||
                        string.Equals(x.Decision.Severity.ToString(), severity, StringComparison.OrdinalIgnoreCase))
            .Reverse()
            .Skip(skip)
            .Take(limit)
            .ToList();
        return Serialize(items);
    }

    private JsonElement FirewallStats()
    {
        var rules = _firewall.ListRules();
        return Serialize(new FirewallRuleStats
        {
            Active = rules.Count,
            Automatic = rules.Count(x => x.Automatic),
            Manual = rules.Count(x => !x.Automatic)
        });
    }

    private async Task<JsonElement> ScanAsync(JsonElement payload, CancellationToken cancellationToken)
    {
        var path = ReadString(payload, "path");
        if (!ScanPathPolicy.IsAllowed(path, ScanPathPolicy.DefaultRoots(), out var error))
            throw new ArgumentException(error);
        if (!File.Exists(path)) throw new FileNotFoundException("fichero no encontrado", path);
        await _scanGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return Serialize(await _pipeline.ScanPathReadOnlyAsync(path, cancellationToken).ConfigureAwait(false));
        }
        finally
        {
            _scanGate.Release();
        }
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
        return Serialize(new { name = spec.Name });
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
        return Serialize(new { removed = true });
    }

    private async Task<JsonElement> RestoreAsync(JsonElement payload)
    {
        var id = ReadString(payload, "id");
        var item = await _quarantine.GetAsync(id).ConfigureAwait(false);
        if (item is null || !await _quarantine.RestoreAsync(id).ConfigureAwait(false))
            throw new InvalidOperationException("elemento no restaurable");
        await _store.MarkRemediatedAsync(item.ThreatId, "restaurado por administrador").ConfigureAwait(false);
        _firewall.RemoveRulesForThreat(item.ThreatId);
        return Serialize(new { restored = true });
    }

    private async Task<JsonElement> PurgeAsync(JsonElement payload)
    {
        var id = ReadString(payload, "id");
        var item = await _quarantine.GetAsync(id).ConfigureAwait(false);
        if (item is null || !await _quarantine.PurgeAsync(id).ConfigureAwait(false))
            throw new InvalidOperationException("elemento no purgable");
        await _store.MarkRemediatedAsync(item.ThreatId, "purgado por administrador").ConfigureAwait(false);
        _firewall.RemoveRulesForThreat(item.ThreatId);
        return Serialize(new { purged = true });
    }

    private JsonElement ChangePolicy(JsonElement payload)
    {
        var policy = Read<PolicySettings>(payload, "policy");
        policy.Validate();
        _config.SavePolicy(policy);
        _state.UpdatePolicy(_config.Policy);
        _store.SetMaxEvents(policy.MaxEvents);
        return Serialize(_state.GetPolicy());
    }

    private static JsonElement Serialize<T>(T value) => JsonSerializer.SerializeToElement(value, JsonDefaults.Options);

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

    private static string? ReadOptionalString(JsonElement payload, string property)
    {
        if (payload.ValueKind != JsonValueKind.Object ||
            !payload.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.String)
            return null;
        return value.GetString();
    }

    private static int ReadInt(JsonElement payload, string property, int fallback)
    {
        if (payload.ValueKind != JsonValueKind.Object ||
            !payload.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out var parsed))
            return fallback;
        return parsed;
    }
}

using System.Runtime.InteropServices;
using System.Runtime.Versioning;

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
    private readonly object _gate = new();

    public string ProductPrefix => "AEGIS Guard";

    public bool IsAvailable()
    {
        try
        {
            _ = CreatePolicy();
            return true;
        }
        catch (COMException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    public string BuildRuleName(FirewallRuleSpec spec)
    {
        var target = spec.ApplicationPath is null ? "any" : Path.GetFileName(spec.ApplicationPath);
        var remote = spec.RemoteAddresses is null ? "any" : spec.RemoteAddresses.Replace('/', '_').Replace(',', '-');
        var port = spec.RemotePort?.ToString() ?? "any";
        var direction = spec.Inbound ? "IN" : "OUT";
        var action = spec.Block ? "BLOCK" : "ALLOW";
        var raw = $"{ProductPrefix} - {action} - {direction} - {target} - {remote} - {port}";
        return raw.Length <= 250 ? raw : raw[..250];
    }

    public bool AddRule(FirewallRuleSpec spec)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(spec.Name);
        lock (_gate)
        {
            dynamic policy = CreatePolicy();
            foreach (dynamic existing in policy.Rules)
            {
                if (string.Equals((string)existing.Name, spec.Name, StringComparison.OrdinalIgnoreCase))
                {
                    existing.Enabled = true;
                    return true;
                }
            }

            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwRule", true)!)!;
            rule.Name = spec.Name;
            rule.Description = spec.Description;
            rule.Action = spec.Block ? NetFwActionBlock : NetFwActionAllow;
            rule.Direction = spec.Inbound ? NetFwRuleDirIn : NetFwRuleDirOut;
            rule.Protocol = spec.Protocol == 0 ? NetFwProtoAny : spec.Protocol;
            rule.Profiles = NetFwProfileAll;
            rule.Enabled = true;
            if (!string.IsNullOrWhiteSpace(spec.ApplicationPath)) rule.ApplicationName = spec.ApplicationPath;
            if (!string.IsNullOrWhiteSpace(spec.RemoteAddresses)) rule.RemoteAddresses = spec.RemoteAddresses;
            if (spec.RemotePort.HasValue) rule.RemotePorts = spec.RemotePort.Value.ToString();
            policy.Rules.Add(rule);
            return true;
        }
    }

    public bool RemoveRule(string name)
    {
        lock (_gate)
        {
            dynamic policy = CreatePolicy();
            foreach (dynamic existing in policy.Rules)
            {
                if (string.Equals((string)existing.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    policy.Rules.Remove(existing.Name);
                    return true;
                }
            }
            return false;
        }
    }

    public List<string> ListRuleNames()
    {
        lock (_gate)
        {
            dynamic policy = CreatePolicy();
            var result = new List<string>();
            foreach (dynamic rule in policy.Rules)
            {
                var name = (string)rule.Name;
                if (name.StartsWith(ProductPrefix, StringComparison.OrdinalIgnoreCase)) result.Add(name);
            }
            return result;
        }
    }

    private static object CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true)
                   ?? throw new InvalidOperationException("El firewall de Windows no está disponible en este equipo.");
        return Activator.CreateInstance(type)
               ?? throw new InvalidOperationException("No se pudo abrir HNetCfg.FwPolicy2; se requieren privilegios de administrador.");
    }
}

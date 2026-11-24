using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

/// <summary>
/// Configuración local de la política. No hay credenciales ni secretos: el
/// producto funciona íntegramente con motores instalados en el equipo.
/// </summary>
public sealed class ConfigStore
{
    private readonly string _path;
    private readonly object _saveGate = new();
    private AppConfig _config;

    private ConfigStore(string path, AppConfig config)
    {
        _path = path;
        _config = config;
    }

    public PolicySettings Policy => Clone(_config.Policy);

    public static ConfigStore Load(string root)
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "config.json");
        AppConfig config;
        if (File.Exists(path))
        {
            try
            {
                config = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(path), JsonDefaults.Options) ?? new AppConfig();
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                config = new AppConfig();
            }
        }
        else config = new AppConfig();

        config.Policy.Validate();
        var store = new ConfigStore(path, config);
        store.Save();
        return store;
    }

    public void SavePolicy(PolicySettings policy)
    {
        policy.Validate();
        _config.Policy = policy;
        Save();
    }

    private void Save()
    {
        lock (_saveGate)
        {
            var temp = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(_config, JsonDefaults.Options));
            File.Move(temp, _path, true);
        }
    }

    private static PolicySettings Clone(PolicySettings p) => new()
    {
        LearningMode = p.LearningMode,
        AutoQuarantine = p.AutoQuarantine,
        AutoBlockNetwork = p.AutoBlockNetwork,
        MonitorThreshold = p.MonitorThreshold,
        BlockThreshold = p.BlockThreshold,
        QuarantineThreshold = p.QuarantineThreshold,
        MaxEvents = p.MaxEvents
    };

    private sealed class AppConfig
    {
        public PolicySettings Policy { get; set; } = new();
    }
}

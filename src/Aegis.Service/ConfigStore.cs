using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using Aegis.Core;

namespace Aegis.Service;

[SupportedOSPlatform("windows")]
public sealed class ConfigStore
{
    private static readonly byte[] Entropy = "AegisGuard.Config.v1"u8.ToArray();
    private readonly string _path;
    private AppConfig _config;

    private ConfigStore(string path, AppConfig config)
    {
        _path = path;
        _config = config;
    }

    public PolicySettings Policy => Clone(_config.Policy);
    public string GatewayUrl => _config.GatewayUrl;
    public string GatewayKey => Unprotect(_config.GatewayKeyProtected);

    public static ConfigStore Load(string root)
    {
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "config.json");
        AppConfig config;
        if (File.Exists(path))
        {
            try { config = JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(path), JsonDefaults.Options) ?? new AppConfig(); }
            catch (JsonException) { config = new AppConfig(); }
        }
        else config = new AppConfig();

        var envKey = Environment.GetEnvironmentVariable("AEGIS_GATEWAY_KEY");
        if (!string.IsNullOrWhiteSpace(envKey)) config.GatewayKeyProtected = Protect(envKey);
        var envUrl = Environment.GetEnvironmentVariable("AEGIS_GATEWAY_URL");
        if (!string.IsNullOrWhiteSpace(envUrl)) config.GatewayUrl = envUrl;

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
        var temp = _path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_config, JsonDefaults.Options));
        File.Move(temp, _path, true);
    }

    private static PolicySettings Clone(PolicySettings p) => new()
    {
        AiEnabled = p.AiEnabled,
        LearningMode = p.LearningMode,
        AutoQuarantine = p.AutoQuarantine,
        AutoBlockNetwork = p.AutoBlockNetwork,
        MonitorThreshold = p.MonitorThreshold,
        BlockThreshold = p.BlockThreshold,
        QuarantineThreshold = p.QuarantineThreshold,
        AiWeight = p.AiWeight,
        MaxEvents = p.MaxEvents
    };

    private static string Protect(string value) => value.Length == 0
        ? string.Empty
        : Convert.ToBase64String(ProtectedData.Protect(System.Text.Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.LocalMachine));

    private static string Unprotect(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        try { return System.Text.Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(value), Entropy, DataProtectionScope.LocalMachine)); }
        catch { return string.Empty; }
    }

    private sealed class AppConfig
    {
        public PolicySettings Policy { get; set; } = new();
        public string GatewayUrl { get; set; } = "http://127.0.0.1:8790";
        public string GatewayKeyProtected { get; set; } = string.Empty;
    }
}

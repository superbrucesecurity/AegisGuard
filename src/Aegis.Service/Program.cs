using System.Text.Json;
using Aegis.Core;
using Aegis.Service;

// El servicio solo recibe la credencial de la pasarela; nunca LIQUID_API_KEY.
EnvFile.Load(allowedKeys: new[] { "AEGIS_GATEWAY_KEY", "AEGIS_GATEWAY_URL" });

var appRoot = AegisPaths.DataRoot;
Directory.CreateDirectory(appRoot);

var config = ConfigStore.Load(appRoot);
var tokens = new ApiTokenProvider(appRoot);
tokens.LoadOrCreate();

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.WebHost.UseUrls("http://127.0.0.1:8787");

builder.Services.AddSingleton(new RuntimeState());
builder.Services.AddSingleton(new EventStore(appRoot, config.Policy.MaxEvents));
builder.Services.AddSingleton(new YaraLiteEngine());
builder.Services.AddSingleton(new ThreatIntel());
builder.Services.AddSingleton<IAiClassifier>(_ => new LiquidGatewayClient(config.GatewayUrl, config.GatewayKey));
builder.Services.AddSingleton(new QuarantineManager(appRoot));
builder.Services.AddSingleton(new FirewallManager());
builder.Services.AddSingleton(new RansomwareCanary(appRoot));
builder.Services.AddSingleton<DetectionPipeline>();
builder.Services.AddHostedService<MonitoringWorker>();

var app = builder.Build();

// AEGIS_RULES_DIR permite editar las reglas de una instalación sin reconstruir.
var rulesDir = Environment.GetEnvironmentVariable("AEGIS_RULES_DIR");
if (string.IsNullOrWhiteSpace(rulesDir)) rulesDir = Path.Combine(AppContext.BaseDirectory, "rules");
var intel = app.Services.GetRequiredService<ThreatIntel>();
intel.Load(Path.Combine(rulesDir, "threat-intel.json"));

var yara = app.Services.GetRequiredService<YaraLiteEngine>();
yara.LoadDirectory(rulesDir);

var store = app.Services.GetRequiredService<EventStore>();
await store.InitializeAsync();
await app.Services.GetRequiredService<QuarantineManager>().InitializeAsync();
app.Services.GetRequiredService<RansomwareCanary>().Initialize();
var state = app.Services.GetRequiredService<RuntimeState>();
state.UpdatePolicy(config.Policy);
// Los KPI deben reflejar el historial cargado, no solo la sesión actual.
state.EventsTotal = store.Observations.Count;
state.ThreatsTotal = store.Threats.Count(x => x.Decision.Verdict != Verdict.Allow);
state.QuarantinedTotal = store.Threats.Count(x => x.Decision.Verdict is Verdict.Quarantine or Verdict.Block);

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

    if (context.Request.Path.StartsWithSegments("/api"))
    {
        var host = context.Request.Host.Host;
        if (host is not ("127.0.0.1" or "localhost" or "[::1]"))
        {
            context.Response.StatusCode = 403;
            return;
        }
        var expected = "Bearer " + tokens.Token;
        if (!string.Equals(context.Request.Headers.Authorization.ToString(), expected, StringComparison.Ordinal))
        {
            context.Response.StatusCode = 401;
            return;
        }
    }
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

var pipeline = app.Services.GetRequiredService<DetectionPipeline>();
var ai = app.Services.GetRequiredService<IAiClassifier>();
var firewall = app.Services.GetRequiredService<FirewallManager>();
var quarantine = app.Services.GetRequiredService<QuarantineManager>();

// healthz es público y no expone estado interno: solo confirma que el proceso responde.
app.MapGet("/healthz", () => Results.Text("ok", "text/plain"));
app.MapGet("/api/health", () => Results.Ok(new { ok = true, version = "1.0.0" }));

app.MapGet("/api/status", () => Results.Json(state.Snapshot(ai, firewall.IsAvailable()), JsonDefaults.Options));

app.MapGet("/api/events", (int limit = 100, int skip = 0, string? severity = null, string? verdict = null) =>
{
    var threats = store.Threats;
    var items = store.Observations
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
        .Skip(Math.Max(0, skip))
        .Take(Math.Clamp(limit, 1, 1000))
        .Select(x => x.node)
        .ToList();
    return Results.Json(items, JsonDefaults.Options);
});

app.MapGet("/api/threats", (int limit = 100, int skip = 0, string? severity = null) =>
    Results.Json(store.Threats
        .Where(x => x.Decision.Verdict != Verdict.Allow)
        .Where(x => string.IsNullOrWhiteSpace(severity) ||
                    string.Equals(x.Decision.Severity.ToString(), severity, StringComparison.OrdinalIgnoreCase))
        .Reverse()
        .Skip(Math.Max(0, skip))
        .Take(Math.Clamp(limit, 1, 1000))
        .ToList(), JsonDefaults.Options));

app.MapGet("/api/quarantine", async () => Results.Json(await quarantine.ListAsync(), JsonDefaults.Options));

app.MapPost("/api/quarantine/{id}/restore", async (string id) =>
{
    var item = await quarantine.GetAsync(id);
    if (item is null) return Results.NotFound(new { error = "elemento no restaurable" });
    try
    {
        if (!await quarantine.RestoreAsync(id))
            return Results.NotFound(new { error = "elemento no restaurable" });
    }
    catch (IOException ex)
    {
        return Results.Conflict(new { error = ex.Message });
    }
    // QuarantineItem.Id y ThreatRecord.Id son GUID distintos: hay que usar
    // ThreatId para que /api/threats refleje la acción del usuario.
    await store.MarkRemediatedAsync(item.ThreatId, "restaurado por usuario");
    // El fichero vuelve al equipo: retirar el bloqueo de red huérfano.
    firewall.RemoveRulesForThreat(item.ThreatId);
    return Results.Ok(new { restored = true });
});

app.MapDelete("/api/quarantine/{id}", async (string id) =>
{
    var item = await quarantine.GetAsync(id);
    if (item is null) return Results.NotFound();
    if (!await quarantine.PurgeAsync(id)) return Results.NotFound();
    await store.MarkRemediatedAsync(item.ThreatId, "purgado por usuario");
    firewall.RemoveRulesForThreat(item.ThreatId);
    return Results.Ok(new { purged = true });
});

app.MapGet("/api/firewall/rules", () => Results.Json(firewall.ListRuleNames(), JsonDefaults.Options));

app.MapPost("/api/firewall/rules", (FirewallRuleSpec spec) =>
{
    spec.Name = spec.Name.StartsWith(firewall.ProductPrefix, StringComparison.OrdinalIgnoreCase)
        ? spec.Name
        : firewall.BuildRuleName(spec);
    var ok = firewall.AddRule(spec);
    return ok ? Results.Ok(new { name = spec.Name }) : Results.BadRequest(new { error = "no se pudo crear la regla" });
});

app.MapDelete("/api/firewall/rules/{**name}", (string name) =>
    firewall.RemoveRule(name) ? Results.Ok(new { removed = true }) : Results.NotFound());

app.MapGet("/api/firewall/learned", () => Results.Json(pipeline.LearnedConnections, JsonDefaults.Options));

app.MapGet("/api/settings", () => Results.Json(state.GetPolicy(), JsonDefaults.Options));

app.MapPut("/api/settings", (PolicySettings policy) =>
{
    policy.Validate();
    // Persistir primero evita que la UI muestre valores rechazados por Validate.
    config.SavePolicy(policy);
    state.UpdatePolicy(config.Policy);
    return Results.Ok(state.GetPolicy());
});

app.MapPost("/api/scan", async (ScanRequest request, CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(request.Path) || !File.Exists(request.Path))
        return Results.BadRequest(new { error = "fichero no encontrado" });
    try
    {
        var threat = await pipeline.ScanPathAsync(request.Path, ct);
        return Results.Json(threat, JsonDefaults.Options);
    }
    catch (Exception ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/ai/test", async (CancellationToken ct) =>
{
    var request = new CloudClassificationRequest
    {
        RequestId = Guid.NewGuid().ToString("N"),
        Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("aegis-connectivity-test"u8.ToArray())).ToLowerInvariant(),
        FileType = "test",
        Signature = SignatureStatus.NotApplicable,
        EventKind = "ManualScan",
        BehaviorFlags = ["connectivity_test"],
        Reputation = 0.5
    };
    // El test de conectividad debe contactar con la pasarela aunque haya una
    // clasificación en caché para esa combinación de señales.
    if (ai is LiquidGatewayClient client) client.InvalidateCache();
    var result = await ai.ClassifyAsync(request, ct);
    state.AiReachable = result.IsValid;
    return Results.Json(result, JsonDefaults.Options);
});

app.MapFallbackToFile("index.html");

app.Run();

public sealed record ScanRequest(string Path);

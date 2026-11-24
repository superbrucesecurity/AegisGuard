using Aegis.Core;
using Aegis.Service;

EnvFile.Load();

var root = Environment.GetEnvironmentVariable("PROGRAMDATA") ?? @"C:\ProgramData";
var appRoot = Path.Combine(root, "AegisGuard");
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

var intel = app.Services.GetRequiredService<ThreatIntel>();
intel.Load(Path.Combine(AppContext.BaseDirectory, "rules", "threat-intel.json"));

var yara = app.Services.GetRequiredService<YaraLiteEngine>();
var rulesDir = Path.Combine(AppContext.BaseDirectory, "rules");
yara.LoadDirectory(rulesDir);

await app.Services.GetRequiredService<EventStore>().InitializeAsync();
await app.Services.GetRequiredService<QuarantineManager>().InitializeAsync();
app.Services.GetRequiredService<RansomwareCanary>().Initialize();
app.Services.GetRequiredService<RuntimeState>().UpdatePolicy(config.Policy);

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

var state = app.Services.GetRequiredService<RuntimeState>();
var store = app.Services.GetRequiredService<EventStore>();
var pipeline = app.Services.GetRequiredService<DetectionPipeline>();
var ai = app.Services.GetRequiredService<IAiClassifier>();
var firewall = app.Services.GetRequiredService<FirewallManager>();
var quarantine = app.Services.GetRequiredService<QuarantineManager>();

app.MapGet("/api/health", () => Results.Ok(new { ok = true, version = "1.0.0" }));

app.MapGet("/api/status", () => Results.Json(state.Snapshot(ai, firewall.IsAvailable()), JsonDefaults.Options));

app.MapGet("/api/events", (int limit = 100) =>
    Results.Json(store.Observations.TakeLast(Math.Clamp(limit, 1, 1000)).Reverse().ToList(), JsonDefaults.Options));

app.MapGet("/api/threats", (int limit = 100) =>
    Results.Json(store.Threats
        .Where(x => x.Decision.Verdict != Verdict.Allow)
        .TakeLast(Math.Clamp(limit, 1, 1000)).Reverse().ToList(), JsonDefaults.Options));

app.MapGet("/api/quarantine", async () => Results.Json(await quarantine.ListAsync(), JsonDefaults.Options));

app.MapPost("/api/quarantine/{id}/restore", async (string id) =>
{
    var restored = await quarantine.RestoreAsync(id);
    if (!restored) return Results.NotFound(new { error = "elemento no restaurable" });
    await store.MarkRemediatedAsync(id, "restaurado por usuario");
    return Results.Ok(new { restored = true });
});

app.MapDelete("/api/quarantine/{id}", async (string id) =>
    await quarantine.PurgeAsync(id) ? Results.Ok(new { purged = true }) : Results.NotFound());

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
    state.UpdatePolicy(policy);
    config.SavePolicy(policy);
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
    var result = await ai.ClassifyAsync(request, ct);
    state.AiReachable = result.IsValid;
    return Results.Json(result, JsonDefaults.Options);
});

app.MapFallbackToFile("index.html");

app.Run();

public sealed record ScanRequest(string Path);

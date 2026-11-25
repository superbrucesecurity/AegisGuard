using System.Text.Json;
using Aegis.Core;
using Aegis.Service;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;

var serviceName = Environment.GetEnvironmentVariable("AEGIS_SERVICE_NAME");
if (string.IsNullOrWhiteSpace(serviceName)) serviceName = "AegisGuardSvc";
// El proveedor del registro de eventos se crea con sc.exe create, que usa el
// nombre del servicio. Usar otro nombre aquí deja los mensajes sin publicar.
var eventSource = serviceName;
var managedByScm = OperatingSystem.IsWindows() &&
    string.Equals(Environment.GetEnvironmentVariable("AEGIS_SERVICE_MANAGED"), "1", StringComparison.Ordinal);

var appRoot = AegisPaths.DataRoot;
Directory.CreateDirectory(appRoot);
// Repara ACL de instalaciones anteriores antes de leer configuración, claves,
// historial o cuarentena. La UI no necesita acceso directo a estos archivos.
if (OperatingSystem.IsWindows()) LocalFileAcl.RestrictTree(appRoot);

var config = ConfigStore.Load(appRoot);

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
if (OperatingSystem.IsWindows())
{
    if (managedByScm)
        builder.Logging.AddEventLog(settings => settings.SourceName = eventSource);
    builder.Host.UseWindowsService(options => options.ServiceName = serviceName);
}
builder.WebHost.UseUrls("http://127.0.0.1:8787");

builder.Services.AddSingleton(new RuntimeState());
builder.Services.AddSingleton(new LocalReputation(Path.Combine(appRoot, "reputation.json")));
builder.Services.AddSingleton(new EventStore(appRoot, config.Policy.MaxEvents));
builder.Services.AddSingleton(new YaraLiteEngine());
builder.Services.AddSingleton(new ThreatIntel());
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
var yara = app.Services.GetRequiredService<YaraLiteEngine>();

// Un paquete firmado y verificado sustituye a las reglas incluidas. Sin la
// huella de la clave fijada en el entorno no se carga ningún paquete externo.
var trustedKeyHash = Environment.GetEnvironmentVariable("AEGIS_INTEL_KEY_SHA256");
var packageDir = Environment.GetEnvironmentVariable("AEGIS_INTEL_PACKAGE_DIR");
string? intelStatus;
string? packageError = null;
if (!string.IsNullOrWhiteSpace(trustedKeyHash) && !string.IsNullOrWhiteSpace(packageDir) &&
    IntelPackage.TryVerify(packageDir, out var package, out packageError))
{
    var keyFile = Path.Combine(packageDir, IntelPackage.PublicKeyFileName);
    // La clave pública fijada no es secreta, pero su integridad sí: se impide
    // que un usuario estándar pueda sustituirla en el directorio del paquete.
    if (OperatingSystem.IsWindows()) LocalFileAcl.Restrict(keyFile);
    var keyDocument = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(keyFile));
    var actualKeyHash = keyDocument.GetProperty("sha256").GetString();
    if (string.Equals(actualKeyHash, trustedKeyHash, StringComparison.OrdinalIgnoreCase))
    {
        intel.Load(Path.Combine(packageDir, IntelPackage.IntelFileName));
        // Solo se cargan reglas incluidas en el manifiesto: un fichero extra
        // colocado en el directorio no amplía la inteligencia activa.
        yara.LoadFiles(package!.Files
            .Where(f => f.Path.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                        f.Path.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
            .Select(f => Path.Combine(packageDir, f.Path)));
        intelStatus = $"verified:{package.Version}";
    }
    else intelStatus = "rejected:untrusted-key";
}
else if (!string.IsNullOrWhiteSpace(trustedKeyHash) || !string.IsNullOrWhiteSpace(packageDir))
{
    intelStatus = $"rejected:{packageError ?? "missing-package"}";
}
else
{
    intel.Load(Path.Combine(rulesDir, IntelPackage.IntelFileName));
    yara.LoadDirectory(rulesDir);
    intelStatus = "bundled";
}
var runtime = app.Services.GetRequiredService<RuntimeState>();
runtime.IntelStatus = intelStatus;
runtime.IntelHashCount = intel.HashCount;
runtime.YaraRuleCount = yara.RuleCount;

var store = app.Services.GetRequiredService<EventStore>();
await store.InitializeAsync();
await app.Services.GetRequiredService<QuarantineManager>().InitializeAsync();
app.Services.GetRequiredService<RansomwareCanary>().Initialize();
var state = app.Services.GetRequiredService<RuntimeState>();
state.ServiceName = serviceName;
state.ManagedByScm = managedByScm;
state.UpdatePolicy(config.Policy);
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStarted.Register(() => app.Logger.LogInformation(
    "Aegis Guard iniciado en modo {Mode} (servicio {ServiceName}).",
    managedByScm ? "SCM" : "consola", serviceName));
lifetime.ApplicationStopping.Register(() =>
{
    state.MonitorActive = false;
    app.Logger.LogInformation("Apagado ordenado de Aegis Guard solicitado.");
});
// Los KPI deben reflejar el historial cargado, no solo la sesión actual.
state.EventsTotal = store.Observations.Count;
state.ThreatsTotal = store.Threats.Count(x => x.Decision.Verdict != Verdict.Allow);
state.QuarantinedTotal = store.Threats.Count(x => x.Decision.Verdict == Verdict.Quarantine);
state.BlockedTotal = store.Threats.Count(x => x.Decision.Verdict == Verdict.Block);

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; object-src 'none'; form-action 'none'; frame-src 'none'; worker-src 'none'; " +
        "frame-ancestors 'none'; base-uri 'none'";

    if (context.Request.Path.StartsWithSegments("/api"))
    {
        var host = context.Request.Host.Host;
        if (host is not ("127.0.0.1" or "localhost" or "[::1]"))
        {
            context.Response.StatusCode = 403;
            return;
        }
        // La API HTTP sólo sirve lecturas y análisis. La credencial Bearer se
        // eliminó: las operaciones sensibles se atienden por tubería con
        // identidad verificada. Se valida el origen para frenar DNS rebinding
        // y solicitudes cross-site desde páginas del propio equipo.
        var origin = context.Request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origin) &&
            !string.Equals(origin, "http://127.0.0.1:8787", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 403;
            return;
        }
        var fetchSite = context.Request.Headers["Sec-Fetch-Site"].ToString();
        if (!string.IsNullOrEmpty(fetchSite) &&
            !string.Equals(fetchSite, "same-origin", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 403;
            return;
        }
        // Las mutaciones sensibles ya no están registradas. Sin esta guarda,
        // MapFallbackToFile podría responder index.html a un POST/DELETE/PUT
        // y hacer creer que la operación existe.
        var isRead = HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method);
        var isAllowedAnalysis =
            HttpMethods.IsPost(context.Request.Method) &&
            (context.Request.Path.Equals("/api/scan", StringComparison.OrdinalIgnoreCase) ||
             context.Request.Path.Equals("/api/selftest/eicar", StringComparison.OrdinalIgnoreCase));
        if (!isRead && !isAllowedAnalysis)
        {
            context.Response.StatusCode = 405;
            return;
        }
    }
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

var pipeline = app.Services.GetRequiredService<DetectionPipeline>();
var firewall = app.Services.GetRequiredService<FirewallManager>();
var quarantine = app.Services.GetRequiredService<QuarantineManager>();

// Superficie administrativa: tubería con ACL, identidad verificada,
// autorización por operación y auditoría de todos los intentos.
if (OperatingSystem.IsWindows())
{
    var privilegedAudit = new PrivilegedAuditLog(appRoot);
    var privilegedDispatcher = new PrivilegedIpcDispatcher(config, state, store, quarantine, firewall);
    var privilegedIpc = new PrivilegedIpcServer(
        PrivilegedIpcEndpoints.PipeNameForCurrentUser(), privilegedDispatcher, privilegedAudit, app.Logger);
    var ipcCts = new CancellationTokenSource();
    _ = Task.Run(() => privilegedIpc.RunAsync(ipcCts.Token));
    lifetime.ApplicationStopping.Register(() => ipcCts.Cancel());
}

// healthz es público y no expone estado interno: solo confirma que el proceso responde.
app.MapGet("/healthz", () => Results.Text("ok", "text/plain"));
app.MapGet("/api/health", () => Results.Ok(new
{
    ok = true,
    version = typeof(ScanRequest).Assembly.GetName().Version?.ToString(3) ?? "3.0.0"
}));

app.MapGet("/api/status", () => Results.Json(state.Snapshot(firewall.IsAvailable()), JsonDefaults.Options));

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

// Las mutaciones de cuarentena, firewall y política NO están expuestas por
// HTTP. Se atienden únicamente por IPC con elevación real y auditoría.

app.MapGet("/api/firewall/rules", () => Results.Json(firewall.ListRuleNames(), JsonDefaults.Options));

app.MapGet("/api/firewall/stats", () =>
{
    var rules = firewall.ListRules();
    return Results.Json(new FirewallRuleStats
    {
        Active = rules.Count,
        Automatic = rules.Count(x => x.Automatic),
        Manual = rules.Count(x => !x.Automatic)
    }, JsonDefaults.Options);
});

app.MapGet("/api/firewall/learned", () => Results.Json(pipeline.LearnedConnections, JsonDefaults.Options));

app.MapGet("/api/settings", () => Results.Json(state.GetPolicy(), JsonDefaults.Options));

app.MapPost("/api/selftest/eicar", async (CancellationToken ct) =>
    Results.Json(await pipeline.SelfTestEicarAsync(ct).ConfigureAwait(false), JsonDefaults.Options));

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

app.MapFallbackToFile("index.html");

app.Run();

public sealed record ScanRequest(string Path);

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
var httpBase = AegisHttpEndpoints.BaseUrl();
builder.WebHost.UseUrls(httpBase);

builder.Services.AddSingleton(new RuntimeState());
builder.Services.AddSingleton(new LocalReputation(Path.Combine(appRoot, "reputation.json")));
builder.Services.AddSingleton(new EventStore(appRoot, config.Policy.MaxEvents));
builder.Services.AddSingleton(new YaraLiteEngine());
builder.Services.AddSingleton(new ThreatIntel());
builder.Services.AddSingleton(new QuarantineManager(appRoot));
builder.Services.AddSingleton(new FirewallManager());
builder.Services.AddSingleton(new RansomwareCanary(appRoot));
builder.Services.AddSingleton(new CorrelationEngine());
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
    IntelPackage.TryVerify(packageDir, trustedKeyHash, out var package, out packageError))
{
    var keyFile = Path.Combine(packageDir, IntelPackage.PublicKeyFileName);
    // La clave pública fijada no es secreta, pero su integridad sí: se impide
    // que un usuario estándar pueda sustituirla en el directorio del paquete.
    if (OperatingSystem.IsWindows()) LocalFileAcl.Restrict(keyFile);
    intel.Load(Path.Combine(packageDir, IntelPackage.IntelFileName));
    // Solo se cargan reglas incluidas en el manifiesto: un fichero extra
    // colocado en el directorio no amplía la inteligencia activa.
    yara.LoadFiles(package!.Files
        .Where(f => f.Path.EndsWith(".yar", StringComparison.OrdinalIgnoreCase) ||
                    f.Path.EndsWith(".yara", StringComparison.OrdinalIgnoreCase))
        .Select(f => Path.Combine(packageDir, f.Path)));
    intelStatus = $"verified:{package.Version}";
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
        "connect-src 'none'; object-src 'none'; form-action 'none'; frame-src 'none'; worker-src 'none'; " +
        "frame-ancestors 'none'; base-uri 'none'";

    // El servicio HTTP publica únicamente archivos estáticos y /healthz.
    // Todas las operaciones de datos, incluidos los análisis, se atienden por
    // la tubería local con identidad verificada (see PrivilegedIpcDispatcher).
    // Las cabeceras de origen se comprueban incluso para estáticos para frenar
    // DNS rebinding contra el enlace de loopback.
    var host = context.Request.Host.Host;
    if (host is not ("127.0.0.1" or "localhost" or "[::1]"))
    {
        context.Response.StatusCode = 403;
        return;
    }
    var origin = context.Request.Headers.Origin.ToString();
    if (!string.IsNullOrEmpty(origin) &&
        !string.Equals(origin, httpBase, StringComparison.OrdinalIgnoreCase))
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
    // Sin esta guarda, MapFallbackToFile respondería index.html con 200 a un
    // POST/DELETE/PUT y simularía una API que ya no existe.
    if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
    {
        context.Response.StatusCode = 405;
        return;
    }
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();

var pipeline = app.Services.GetRequiredService<DetectionPipeline>();
var firewall = app.Services.GetRequiredService<FirewallManager>();
var quarantine = app.Services.GetRequiredService<QuarantineManager>();

// Superficie de datos: tubería local con ACL, identidad verificada,
// autorización por SID y por operación, y auditoría de todos los intentos.
// La interfaz no expone operaciones por HTTP, ni siquiera lecturas.
if (OperatingSystem.IsWindows())
{
    var privilegedAudit = new PrivilegedAuditLog(appRoot, app.Logger);
    var privilegedDispatcher = new PrivilegedIpcDispatcher(
        config, state, store, quarantine, firewall, pipeline);
    var privilegedIpc = new PrivilegedIpcServer(
        PrivilegedIpcEndpoints.PipeNameForCurrentUser(), privilegedDispatcher, privilegedAudit, app.Logger);
    var ipcCts = new CancellationTokenSource();
    _ = Task.Run(() => privilegedIpc.RunAsync(ipcCts.Token));
    lifetime.ApplicationStopping.Register(() => ipcCts.Cancel());
}

// healthz es público y no expone estado interno: solo confirma que el proceso responde.
app.MapGet("/healthz", () => Results.Text("ok", "text/plain"));
app.MapFallbackToFile("index.html");

app.Run();

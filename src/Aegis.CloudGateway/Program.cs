using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Aegis.Core;

Aegis.Core.EnvFile.Load();

var builder = WebApplication.CreateBuilder(args);
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

var gatewayKey = Environment.GetEnvironmentVariable("AEGIS_GATEWAY_KEY") ?? string.Empty;
if (gatewayKey.Length < 24)
{
    Console.Error.WriteLine("AEGIS_GATEWAY_KEY debe tener al menos 24 caracteres.");
    return 1;
}

var liquidKey = Environment.GetEnvironmentVariable("LIQUID_API_KEY") ?? string.Empty;
// Algunas copias del portal omiten el prefijo "liquid". Se restaura aquí para
// que el gateway acepte tanto la clave completa como su sufijo.
if (liquidKey.Length > 0 && !liquidKey.StartsWith("liquid", StringComparison.OrdinalIgnoreCase))
    liquidKey = "liquid" + liquidKey;
var model = Environment.GetEnvironmentVariable("LIQUID_MODEL") ?? "d1.2-ultra";
if (model is not ("d1.2-ultra" or "d1.2"))
{
    Console.Error.WriteLine("LIQUID_MODEL debe ser d1.2-ultra o d1.2.");
    return 1;
}

builder.Services.AddSingleton(new LiquidOptions(liquidKey, model));
builder.Services.AddSingleton<LiquidDecisionClient>();
builder.Services.AddSingleton<GatewayRateLimiter>();
builder.WebHost.UseUrls(Environment.GetEnvironmentVariable("ASPNETCORE_URLS") ?? "http://127.0.0.1:8790");

var app = builder.Build();
var json = new JsonSerializerOptions(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

app.MapGet("/healthz", (LiquidOptions options, LiquidDecisionClient client) => Results.Json(new
{
    status = options.HasKey ? "ready" : "degraded",
    model = options.Model,
    totalCalls = client.Calls,
    lastError = client.LastError
}, json));

app.MapPost("/v1/classify", async (
    HttpContext ctx,
    CloudClassificationRequest request,
    LiquidDecisionClient client,
    GatewayRateLimiter limiter,
    CancellationToken ct) =>
{
    if (!ctx.Request.Headers.TryGetValue("X-Aegis-Key", out var provided) || provided.ToString() != gatewayKey)
        return Results.StatusCode(401);
    if (!limiter.Allow(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown"))
        return Results.StatusCode(429);
    if (!IsValidRequest(request))
        return Results.BadRequest(new { error = "invalid_request" });

    var result = await client.ClassifyAsync(request, ct).ConfigureAwait(false);
    return Results.Json(result, json);
});

app.Run();
return 0;

static bool IsValidRequest(CloudClassificationRequest r)
{
    if (r is null) return false;
    if (r.Sha256.Length is not 64 || !r.Sha256.All(Uri.IsHexDigit)) return false;
    if (r.BehaviorFlags.Count > 24 || r.RuleIds.Count > 24) return false;
    if (r.BehaviorFlags.Any(x => x.Length > 80) || r.RuleIds.Any(x => x.Length > 80)) return false;
    if (r.SizeBucket < 0 || r.Reputation is < 0 or > 1) return false;
    if (!new[] { "FileCreated", "FileModified", "ProcessStarted", "NetworkConnection", "DnsQuery", "RegistryChanged", "ServiceChanged", "PersistenceChanged", "ManualScan" }.Contains(r.EventKind)) return false;
    return true;
}

sealed record LiquidOptions(string ApiKey, string Model)
{
    public bool HasKey => !string.IsNullOrWhiteSpace(ApiKey);
}

sealed class GatewayRateLimiter
{
    private readonly ConcurrentDictionary<string, (int Count, long Window)> _windows = new();
    public bool Allow(string key)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var window = now / 60;
        var entry = _windows.AddOrUpdate(key, _ => (1, window), (_, old) => old.Window == window ? (old.Count + 1, window) : (1, window));
        return entry.Count <= 120;
    }
}

sealed class LiquidDecisionClient
{
    private readonly LiquidOptions _options;
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions LiquidJson = new(JsonSerializerDefaults.General);
    private long _calls;
    private long _suppressedUntil;
    public long Calls => Interlocked.Read(ref _calls);
    public string? LastError { get; private set; }

    public LiquidDecisionClient(LiquidOptions options)
    {
        _options = options;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", options.ApiKey);
    }

    public async Task<CloudClassificationResponse> ClassifyAsync(CloudClassificationRequest r, CancellationToken ct)
    {
        var started = Environment.TickCount64;
        Interlocked.Increment(ref _calls);
        var suppressedUntil = Interlocked.Read(ref _suppressedUntil);
        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < suppressedUntil)
        {
            LastError = $"limitado por Liquid: reintento en {suppressedUntil - DateTimeOffset.UtcNow.ToUnixTimeSeconds()}s";
            return Fail(r, LastError);
        }
        if (!_options.HasKey)
        {
            LastError = "LIQUID_API_KEY missing";
            return Fail(r, "clasificador no configurado");
        }

        var state = new
        {
            evidence = new
            {
                eventKind = r.EventKind,
                fileType = r.FileType,
                sizeBucket = r.SizeBucket,
                signature = r.Signature.ToString(),
                reputation = Math.Round(r.Reputation, 2),
                behaviorFlags = r.BehaviorFlags.Take(16),
                localRuleIds = r.RuleIds.Take(16),
                sha256Prefix = r.Sha256[..12]
            },
            guidance = "Only use the supplied evidence. Unknown or insufficient evidence must favor CLEAN or SUSPICIOUS, never MALICIOUS."
        };

        var payload = new
        {
            model = _options.Model,
            state,
            questions = new
            {
                classification = new
                {
                    type = "choice",
                    instructions = "Classify this security event using only the supplied indicators.",
                    criteria = new
                    {
                        CLEAN = "Known-good or ordinary activity; no meaningful malicious indicators.",
                        SUSPICIOUS = "Unusual or uncertain activity that merits monitoring but not automatic blocking.",
                        MALICIOUS = "Strong, specific indicators of malware, ransomware, credential theft or C2 activity."
                    }
                },
                malwareProbability = new
                {
                    type = "noul",
                    instructions = "Is there strong evidence of malicious software or malicious intent in these indicators?"
                },
                severity = new
                {
                    type = "score",
                    instructions = "How severe is the risk if the indicators are true?",
                    criteria = new[]
                    {
                        "Informational: no impact expected",
                        "Low: minor or isolated anomaly",
                        "Medium: suspicious behavior requiring review",
                        "Critical: ransomware, credential theft, rootkit or active C2"
                    }
                }
            }
        };

        try
        {
            using var response = await _http.PostAsJsonAsync("https://api.liquid.ai/decisions/v1/systemone", payload, LiquidJson, ct).ConfigureAwait(false);
            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if ((int)response.StatusCode is 429 or 503)
            {
                var retry = response.Headers.RetryAfter?.Delta?.TotalSeconds
                            ?? (response.Headers.RetryAfter?.Date is { } date ? (date - DateTimeOffset.UtcNow).TotalSeconds : 5);
                var seconds = (long)Math.Clamp(Math.Ceiling(retry), 1, 120);
                Interlocked.Exchange(ref _suppressedUntil, DateTimeOffset.UtcNow.AddSeconds(seconds).ToUnixTimeSeconds());
                LastError = $"limitado por Liquid: reintento en {seconds}s";
                return Fail(r, LastError);
            }
            if (!response.IsSuccessStatusCode)
            {
                LastError = $"Liquid API HTTP {(int)response.StatusCode}";
                return Fail(r, LastError);
            }

            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            if (!root.TryGetProperty("answers", out var answers)) return Fail(r, "respuesta sin answers");

            var choice = answers.GetProperty("classification");
            var label = (choice.GetProperty("choice").GetString() ?? string.Empty).Trim().ToUpperInvariant();
            var probs = choice.GetProperty("probabilities");
            var clean = GetProb(probs, "CLEAN");
            var suspicious = GetProb(probs, "SUSPICIOUS");
            var malicious = GetProb(probs, "MALICIOUS");
            var confidence = choice.TryGetProperty("confidence", out var conf) && conf.TryGetDouble(out var c) ? c : 0;
            var noul = answers.GetProperty("malwareProbability").TryGetProperty("noul", out var n) && n.TryGetDouble(out var nd) ? nd : 0;
            var severity = answers.GetProperty("severity").GetProperty("score").GetDouble();
            var tokens = root.TryGetProperty("usage", out var usage) && usage.TryGetProperty("input_tokens", out var t) ? t.GetInt32() : 0;

            if (label is not ("CLEAN" or "SUSPICIOUS" or "MALICIOUS"))
            {
                LastError = $"etiqueta desconocida: '{label}'";
                return Fail(r, LastError);
            }
            if (tokens is <= 0 or > 70000) return Fail(r, "uso de tokens fuera de rango");
            if (new[] { clean, suspicious, malicious, confidence, noul }.Any(v => v is < 0 or > 1 or double.NaN)) return Fail(r, "probabilidad fuera de rango");
            var probabilitySum = clean + suspicious + malicious;
            if (probabilitySum is < 0.85 or > 1.15)
            {
                LastError = $"distribución inválida sum={probabilitySum:F3} claves=[{string.Join(',', probs.EnumerateObject().Select(p => p.Name))}]";
                return Fail(r, LastError);
            }

            LastError = null;
            return new CloudClassificationResponse
            {
                RequestId = r.RequestId,
                Model = _options.Model,
                ChoiceLabel = label,
                Clean = clean,
                Suspicious = suspicious,
                Malicious = Math.Max(malicious, noul * 0.5),
                Confidence = confidence,
                SeverityScore = Math.Clamp(severity, 0, 3),
                IsValid = true,
                LatencyMs = Environment.TickCount64 - started,
                InputTokens = tokens
            };
        }
        catch (HttpRequestException ex) { LastError = ex.Message; return Fail(r, "error de red con Liquid API"); }
        catch (TaskCanceledException) { LastError = "timeout"; return Fail(r, "timeout con Liquid API"); }
        catch (JsonException) { LastError = "json inválido"; return Fail(r, "respuesta IA mal formada"); }
        catch (KeyNotFoundException) { LastError = "campos ausentes"; return Fail(r, "respuesta IA incompleta"); }
    }

    private static double GetProb(JsonElement probs, string key)
    {
        if (probs.TryGetProperty(key, out var p) && p.TryGetDouble(out var v)) return v;
        foreach (var property in probs.EnumerateObject())
            if (string.Equals(property.Name, key, StringComparison.OrdinalIgnoreCase) &&
                property.Value.TryGetDouble(out var value)) return value;
        return 0;
    }

    private static CloudClassificationResponse Fail(CloudClassificationRequest r, string error) => new()
    {
        RequestId = r.RequestId,
        Model = "none",
        ChoiceLabel = "INDETERMINATE",
        IsValid = false,
        Error = error
    };
}

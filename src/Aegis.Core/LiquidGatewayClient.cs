using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace Aegis.Core;

public interface IAiClassifier
{
    Task<AiClassification> ClassifyAsync(CloudClassificationRequest request, CancellationToken ct = default);
}

/// <summary>
/// Cliente del backend intermediario. El cliente Windows nunca ve la clave de
/// Liquid AI: solo una clave de servicio rotatoria para la pasarela.
/// </summary>
public sealed class LiquidGatewayClient : IAiClassifier
{
    private readonly HttpClient _http;
    private readonly string _gatewayKey;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new();
    private int _failures;
    private DateTimeOffset _circuitOpenUntil;

    private long _cacheHits;
    private long _calls;
    public long CacheHits => Interlocked.Read(ref _cacheHits);
    public long Calls => Interlocked.Read(ref _calls);

    public LiquidGatewayClient(string baseUrl, string gatewayKey, TimeSpan? timeout = null)
        : this(baseUrl, gatewayKey, new HttpClientHandler(), timeout)
    {
    }

    public LiquidGatewayClient(string baseUrl, string gatewayKey, HttpMessageHandler handler, TimeSpan? timeout = null)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("URL de pasarela no válida", nameof(baseUrl));
        _http = new HttpClient(handler) { BaseAddress = uri, Timeout = timeout ?? TimeSpan.FromSeconds(6) };
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _gatewayKey = gatewayKey;
    }

    public async Task<AiClassification> ClassifyAsync(CloudClassificationRequest request, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_gatewayKey))
            return Failure("gateway-key-missing", "La pasarela IA no está configurada");

        if (DateTimeOffset.UtcNow < _circuitOpenUntil)
            return Failure("circuit-open", "Clasificador temporalmente no disponible");

        var cacheKey = BuildCacheKey(request);
        if (_cache.TryGetValue(cacheKey, out var cached) && cached.Expires > DateTimeOffset.UtcNow)
        {
            Interlocked.Increment(ref _cacheHits);
            return cached.Value;
        }

        Interlocked.Increment(ref _calls);
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, "/v1/classify");
            message.Headers.Add("X-Aegis-Key", _gatewayKey);
            message.Content = JsonContent.Create(request, options: JsonDefaults.Options);
            using var response = await _http.SendAsync(message, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden)
                return RegisterFailure("gateway-auth", "La pasarela rechazó la credencial");
            if (!response.IsSuccessStatusCode)
                return RegisterFailure("gateway-error", $"HTTP {(int)response.StatusCode}");

            var payload = await response.Content.ReadFromJsonAsync<GatewayResponse>(JsonDefaults.Options, ct).ConfigureAwait(false);
            if (payload is null) return Failure("empty-response", "Respuesta vacía de la pasarela");
            if (payload.Error?.StartsWith("limitado", StringComparison.OrdinalIgnoreCase) == true)
                return RegisterFailure("rate-limited", payload.Error);

            var classification = new AiClassification
            {
                Model = payload.Model ?? "unknown",
                ChoiceLabel = payload.ChoiceLabel ?? "INDETERMINATE",
                Clean = Clamp(payload.Clean),
                Suspicious = Clamp(payload.Suspicious),
                Malicious = Clamp(payload.Malicious),
                Confidence = Clamp(payload.Confidence),
                SeverityScore = Math.Clamp(payload.SeverityScore, 0, 3),
                LatencyMs = payload.LatencyMs,
                RequestId = payload.RequestId ?? request.RequestId,
                IsValid = Validate(payload),
                Error = payload.Error
            };
            if (!classification.IsValid) classification.Error ??= "Respuesta IA fuera de rango";

            Interlocked.Exchange(ref _failures, 0);
            _cache[cacheKey] = new CacheEntry(classification, DateTimeOffset.UtcNow.AddMinutes(15));
            return classification;
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            return RegisterFailure("timeout", "Tiempo de espera agotado");
        }
        catch (HttpRequestException)
        {
            return RegisterFailure("network", "No se pudo contactar con la pasarela");
        }
        catch (Exception ex)
        {
            return RegisterFailure("invalid-response", ex.Message);
        }
    }

    private AiClassification RegisterFailure(string code, string message)
    {
        var failures = Interlocked.Increment(ref _failures);
        if (failures >= 3) _circuitOpenUntil = DateTimeOffset.UtcNow.AddSeconds(30);
        return Failure(code, message);
    }

    private static AiClassification Failure(string error, string message) => new()
    {
        IsValid = false,
        Error = $"{error}: {message}",
        ChoiceLabel = "INDETERMINATE"
    };

    private static bool Validate(GatewayResponse p)
    {
        if (p is null || !p.IsValid) return false;
        if (p.ChoiceLabel is not ("CLEAN" or "SUSPICIOUS" or "MALICIOUS")) return false;
        if (new[] { p.Clean, p.Suspicious, p.Malicious, p.Confidence }.Any(v => v is < 0 or > 1 or double.NaN)) return false;
        var sum = p.Clean + p.Suspicious + p.Malicious;
        return sum is >= 0.85 and <= 1.15;
    }

    private static double Clamp(double value) => double.IsFinite(value) ? Math.Clamp(value, 0, 1) : 0;

    private static string BuildCacheKey(CloudClassificationRequest r) =>
        $"{r.Sha256}|{(int)r.Signature}|{r.FileType}|{r.SizeBucket}|{string.Join(',', r.BehaviorFlags.Order())}|{string.Join(',', r.RuleIds.Order())}|{(int)r.Reputation * 20}";

    private sealed record CacheEntry(AiClassification Value, DateTimeOffset Expires);

    private sealed class GatewayResponse
    {
        [JsonPropertyName("model")] public string? Model { get; set; }
        [JsonPropertyName("choiceLabel")] public string? ChoiceLabel { get; set; }
        [JsonPropertyName("clean")] public double Clean { get; set; }
        [JsonPropertyName("suspicious")] public double Suspicious { get; set; }
        [JsonPropertyName("malicious")] public double Malicious { get; set; }
        [JsonPropertyName("confidence")] public double Confidence { get; set; }
        [JsonPropertyName("severityScore")] public double SeverityScore { get; set; }
        [JsonPropertyName("isValid")] public bool IsValid { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("latencyMs")] public long LatencyMs { get; set; }
        [JsonPropertyName("requestId")] public string? RequestId { get; set; }
    }
}

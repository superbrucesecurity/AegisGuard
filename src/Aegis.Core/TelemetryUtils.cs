using System.Collections.Concurrent;
using System.Globalization;
using System.Net;

namespace Aegis.Core;

/// <summary>
/// Normalización de payloads ETW. Los eventos de red de Microsoft-Windows-Kernel-Network
/// entregan daddr/saddr como Int32 little-endian: 16777343 es 127.0.0.1 y
/// 234924224 es 192.168.0.14. IPAddress.TryParse con un número suelto lo interpreta
/// como big-endian, por lo que las cadenas numéricas se convierten por separado.
/// </summary>
public static class TelemetryAddress
{
    public static string? Normalize(object? raw)
    {
        if (raw is null) return null;
        if (raw is byte[] bytes && bytes.Length is 4 or 16)
            return new IPAddress(bytes).ToString();

        var text = raw.ToString()?.Trim();
        if (string.IsNullOrWhiteSpace(text)) return null;

        // "1.2.3.4:443" llega en algunos payloads; normalizar ambas partes evita
        // reglas WFP con una dirección inválida.
        if (text.Contains(':') && text.Count(c => c == ':') == 1 && !text.StartsWith('['))
        {
            var separator = text.LastIndexOf(':');
            if (separator > 0 && IPAddress.TryParse(text[..separator], out var endpointAddress))
                return endpointAddress.ToString();
        }

        if (text.Contains('.') || text.Contains(':'))
            return IPAddress.TryParse(text, out var parsed) ? parsed.ToString() : text;

        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
            return new IPAddress(BitConverter.GetBytes(unchecked((uint)numeric))).ToString();
        return text;
    }

    public static string? NormalizePort(object? raw)
    {
        var text = raw?.ToString()?.Trim();
        if (string.IsNullOrWhiteSpace(text)) return null;
        // Un puerto corrupto nunca debe convertirse en otro puerto válido:
        // acabaría en una regla WFP bloqueando el servicio equivocado.
        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric) &&
            numeric is >= 1 and <= 65535)
            return numeric.ToString(CultureInfo.InvariantCulture);
        return null;
    }
}

/// <summary>
/// Deduplicación por clave con ventana deslizante. Usa TryAdd/TryUpdate en lugar de
/// comparar valores de AddOrUpdate: varios eventos en el mismo milisegundo tienen
/// la misma marca de tiempo y de otro modo se contarían como nuevos.
/// </summary>
public sealed class EventDeduplicator
{
    private readonly ConcurrentDictionary<string, long> _cache = new();

    public bool IsDuplicate(string key, long windowMs)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var now = Environment.TickCount64;
        if (_cache.TryAdd(key, now))
        {
            if (_cache.Count > 5000)
                foreach (var expired in _cache.Where(x => now - x.Value >= windowMs).Select(x => x.Key))
                    _cache.TryRemove(expired, out _);
            return false;
        }
        if (_cache.TryGetValue(key, out var last) && now - last >= windowMs && _cache.TryUpdate(key, now, last))
            return false;
        return true;
    }
}

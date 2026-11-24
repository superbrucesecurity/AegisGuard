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

        var text = raw.ToString();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (text.Contains('.') || text.Contains(':'))
            return IPAddress.TryParse(text, out var parsed) ? parsed.ToString() : text;

        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
            return new IPAddress(BitConverter.GetBytes(unchecked((uint)numeric))).ToString();
        return text;
    }

    public static string? NormalizePort(object? raw)
    {
        var text = raw?.ToString();
        if (string.IsNullOrWhiteSpace(text)) return null;
        if (ushort.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
            return port.ToString(CultureInfo.InvariantCulture);
        if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var numeric))
            return ((ushort)numeric).ToString(CultureInfo.InvariantCulture);
        return text;
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
        if (_cache.TryAdd(key, now)) return false;
        if (_cache.TryGetValue(key, out var last) && now - last >= windowMs && _cache.TryUpdate(key, now, last))
            return false;
        if (_cache.Count > 5000) _cache.Clear();
        return true;
    }
}

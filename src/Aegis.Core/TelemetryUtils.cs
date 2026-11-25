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

    /// <summary>
    /// Clasificación determinista de IP pública compartida por la decisión y la
    /// correlación. Loopback, privadas, link-local, ULA y redes de documentación
    /// no cuentan como destino público.
    /// </summary>
    public static bool IsPublicIp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !IPAddress.TryParse(value.Trim(), out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return false;

        var b = ip.GetAddressBytes();
        if (b.Length == 16)
        {
            if ((b[0] & 0xfe) == 0xfc) return false;           // fc00::/7 ULA
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false; // fe80::/10
            if (b[0] == 0xff) return false;                   // multicast
            return true;
        }

        if (b[0] == 0 || b[0] >= 224 || b[0] == 127) return false;
        if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
            (b[0] == 192 && b[1] == 168)) return false;
        if (b[0] == 169 && b[1] == 254) return false;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
        if (b[0] == 192 && b[1] == 0 && b[2] == 0) return false;
        if (b[0] == 192 && b[1] == 0 && b[2] == 2) return false;        // TEST-NET-1
        if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;
        if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;     // TEST-NET-2
        if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;      // TEST-NET-3
        return true;
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

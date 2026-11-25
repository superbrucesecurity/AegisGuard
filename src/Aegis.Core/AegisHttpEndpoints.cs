namespace Aegis.Core;

/// <summary>
/// Extremo HTTP local compartido por servicio y UI. El puerto es configurable
/// para que una verificación aislada pueda usar uno libre sin interferir con
/// otra instancia; el valor por defecto sigue siendo 8787.
/// </summary>
public static class AegisHttpEndpoints
{
    public const int DefaultPort = 8787;

    public static int Port()
    {
        var configured = Environment.GetEnvironmentVariable("AEGIS_HTTP_PORT");
        return int.TryParse(configured, out var port) && port is >= 1 and <= 65535
            ? port
            : DefaultPort;
    }

    public static string BaseUrl() => $"http://127.0.0.1:{Port()}";

    public static string DashboardUrl() => BaseUrl() + "/";

    public static bool IsLocalDashboard(Uri uri) =>
        uri.Scheme == Uri.UriSchemeHttp &&
        string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal) &&
        uri.Port == Port();
}

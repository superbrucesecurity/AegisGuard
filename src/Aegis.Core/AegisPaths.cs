namespace Aegis.Core;

/// <summary>
/// Directorio de estado de la aplicación. AEGIS_DATA_DIR permite aislar una
/// instalación de prueba sin tocar C:\ProgramData; por defecto se usa ProgramData.
/// El producto no lee archivos de configuración externos ni credenciales.
/// </summary>
public static class AegisPaths
{
    public static string DataRoot
    {
        get
        {
            var configured = Environment.GetEnvironmentVariable("AEGIS_DATA_DIR");
            return string.IsNullOrWhiteSpace(configured)
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AegisGuard")
                : Path.GetFullPath(configured);
        }
    }
}

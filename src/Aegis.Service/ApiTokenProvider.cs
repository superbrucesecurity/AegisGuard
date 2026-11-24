using System.Security.Cryptography;
using System.Text;

namespace Aegis.Service;

/// <summary>
/// Token local de la API. El archivo se crea con ACL restringida y, si ya
/// existía con permisos débiles, se reparan al cargarlo.
/// </summary>
public sealed class ApiTokenProvider
{
    private readonly string _path;

    public ApiTokenProvider(string root)
    {
        _path = Path.Combine(root, "ui-token");
    }

    public string Token { get; private set; } = string.Empty;

    public void LoadOrCreate()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        if (File.Exists(_path))
        {
            Token = File.ReadAllText(_path).Trim();
            if (Token.Length >= 32)
            {
                RepairAcl();
                return;
            }
        }

        Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using (var stream = new FileStream(_path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            var bytes = Encoding.ASCII.GetBytes(Token);
            stream.Write(bytes, 0, bytes.Length);
        }
        RepairAcl();
    }

    private void RepairAcl()
    {
        if (OperatingSystem.IsWindows() && !LocalFileAcl.Restrict(_path))
            throw new IOException("No se pudieron restringir los permisos de ui-token.");
    }
}

using System.Security.Cryptography;

namespace Aegis.Service;

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
            if (Token.Length >= 32) return;
        }
        Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        File.WriteAllText(_path, Token);
    }
}

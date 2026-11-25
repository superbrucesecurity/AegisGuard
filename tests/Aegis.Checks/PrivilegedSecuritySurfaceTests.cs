using Aegis.Core;
using Aegis.Service;

namespace Aegis.Checks;

/// <summary>
/// Guardas de regressión de la superficie P0. Evitan que una futura edición
/// reintroduzca el token o devuelva las mutaciones a la API HTTP sin que las
/// pruebas lo detecten.
/// </summary>
public class PrivilegedSecuritySurfaceTests
{
    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "AegisGuard.slnx")))
            directory = directory.Parent;
        return directory?.FullName
            ?? throw new InvalidOperationException("No se encontró la raíz del repositorio.");
    }

    private static string Read(params string[] parts) =>
        File.ReadAllText(Path.Combine(new[] { RepoRoot() }.Concat(parts).ToArray()));

    [Fact]
    public void LaApiHttpNoContieneTokenNiMutacionesSensibles()
    {
        var program = Read("src", "Aegis.Service", "Program.cs");
        Assert.DoesNotContain("ApiTokenProvider", program);
        Assert.DoesNotContain("Authorization", program);
        Assert.DoesNotContain("MapPost(\"/api/quarantine", program);
        Assert.DoesNotContain("MapDelete(\"/api/quarantine", program);
        Assert.DoesNotContain("MapPost(\"/api/firewall/rules", program);
        Assert.DoesNotContain("MapDelete(\"/api/firewall/rules/", program);
        Assert.DoesNotContain("MapPut(\"/api/settings", program);
    }

    [Fact]
    public void LaSpaNoRecibeCredenciales()
    {
        var script = Read("src", "Aegis.Service", "wwwroot", "app.js");
        Assert.DoesNotContain("AEGIS_TOKEN", script);
        Assert.DoesNotContain("Bearer", script);
        Assert.DoesNotContain("authRefreshPending", script);
        Assert.Contains("privilegedCall", script);
    }

    [Fact]
    public void ElProveedorDeTokenYaNoEstaEnElCodigo()
    {
        Assert.False(File.Exists(Path.Combine(RepoRoot(), "src", "Aegis.Service", "ApiTokenProvider.cs")));
        var register = Read("deploy", "Register-Service.ps1");
        Assert.DoesNotContain("ui-token", register);
        Assert.DoesNotContain("Authorization =", register);
        var finish = Read("deploy", "finish.cmd");
        Assert.DoesNotContain("USERSID", finish);
    }

    [Fact]
    public void ServicioYUiDerivanElMismoNombreDeTuberia()
    {
        const string sid = "S-1-5-21-100-200-300-1001";
        Assert.Equal(AegisIpcNames.PrivilegedPipe(sid), PrivilegedIpcEndpoints.PipeNameForSid(sid));
    }

    [Fact]
    public void LosRidsDeIntegridadSiguenAWinnt()
    {
        Assert.Equal(0x1000, NativeClientIdentity.LowIntegrityRid);
        Assert.Equal(0x2000, NativeClientIdentity.MediumIntegrityRid);
        Assert.Equal(0x3000, NativeClientIdentity.HighIntegrityRid);
        Assert.Equal(0x4000, NativeClientIdentity.SystemIntegrityRid);
    }

    [Theory]
    [InlineData(0x4000, "system")]
    [InlineData(0x3000, "high")]
    [InlineData(0x2000, "medium")]
    [InlineData(0x1000, "low")]
    [InlineData(0, "untrusted")]
    public void LaIntegridadSeClasificaConUmbralesCorrectos(int rid, string expected)
    {
        var identity = new ClientIdentity(10, "S-1-5-21-1", rid, TokenElevationType.Full, true, true);
        Assert.Equal(expected, identity.IntegrityName);
    }

    [Fact]
    public void ElDespachadorRechazaReglasAllow()
    {
        var allow = new FirewallRuleSpec { Name = "AEGIS Guard - ALLOW", Block = false, RemotePort = 443 };
        var ex = Assert.Throws<ArgumentException>(() => PrivilegedIpcDispatcher.EnsureBlockOnly(allow));
        Assert.Contains("Allow", ex.Message);
    }

    [Fact]
    public void ElDespachadorAceptaSoloReglasDeBloqueoValidas()
    {
        var block = new FirewallRuleSpec { Name = "AEGIS Guard - BLOCK", Block = true, RemotePort = 443 };
        PrivilegedIpcDispatcher.EnsureBlockOnly(block);

        Assert.Throws<ArgumentException>(() => PrivilegedIpcDispatcher.EnsureBlockOnly(
            new FirewallRuleSpec { Name = block.Name, Block = true, RemotePort = 70000 }));
        Assert.Throws<ArgumentException>(() => PrivilegedIpcDispatcher.EnsureBlockOnly(
            new FirewallRuleSpec { Name = block.Name, Block = true, Protocol = 999 }));
    }
}

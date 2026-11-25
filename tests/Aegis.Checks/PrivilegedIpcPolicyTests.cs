using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Aegis.Core;
using Aegis.Service;

namespace Aegis.Checks;

public class PrivilegedIpcPolicyTests
{
    private static ClientIdentity Standard() => new(
        4242, "S-1-5-21-100-200-300-1001",
        NativeClientIdentity.MediumIntegrityRid,
        TokenElevationType.Limited,
        IsAdministrator: true,
        IsInteractive: true);

    private static ClientIdentity Elevated() => new(
        4242, "S-1-5-21-100-200-300-1001",
        NativeClientIdentity.HighIntegrityRid,
        TokenElevationType.Full,
        IsAdministrator: true,
        IsInteractive: true);

    private static readonly PrivilegedOperation[] Mutaciones =
    {
        PrivilegedOperation.FirewallAddRule, PrivilegedOperation.FirewallRemoveRule,
        PrivilegedOperation.QuarantineRestore, PrivilegedOperation.QuarantinePurge,
        PrivilegedOperation.PolicyChange
    };

    [Fact]
    public void SoloLasMutacionesExigenClearanceElevada()
    {
        foreach (PrivilegedOperation operation in Enum.GetValues<PrivilegedOperation>())
        {
            var mutacion = Mutaciones.Contains(operation);
            Assert.Equal(mutacion ? ClientClearance.Elevated : ClientClearance.Standard,
                PrivilegedOperationPolicy.Required(operation));
            Assert.Equal(!mutacion, PrivilegedOperationPolicy.IsAllowed(Standard(), operation));
            Assert.True(PrivilegedOperationPolicy.IsAllowed(Elevated(), operation));
        }
    }

    [Fact]
    public void TokenLimitadoNoAutorizaMutacionesAunqueElSidSeaAdministrador()
    {
        var limited = Elevated() with { Elevation = TokenElevationType.Limited };
        foreach (var operation in Mutaciones)
            Assert.False(PrivilegedOperationPolicy.IsAllowed(limited, operation));
        Assert.True(PrivilegedOperationPolicy.IsAllowed(limited, PrivilegedOperation.Status));
        Assert.Contains("limitado", PrivilegedOperationPolicy.DenialReason(limited, PrivilegedOperation.PolicyChange));
    }

    [Fact]
    public void IntegridadMediaAutorizaLecturasPeroNoMutaciones()
    {
        var medium = Elevated() with { IntegrityRid = NativeClientIdentity.MediumIntegrityRid };
        Assert.False(PrivilegedOperationPolicy.IsAllowed(medium, PrivilegedOperation.FirewallAddRule));
        Assert.True(PrivilegedOperationPolicy.IsAllowed(medium, PrivilegedOperation.Status));
        Assert.Equal(ClientClearance.Standard, medium.Clearance);
    }

    [Fact]
    public void ProcesoNoInteractivoNoAutoriza()
    {
        var background = Elevated() with { IsInteractive = false };
        Assert.False(PrivilegedOperationPolicy.IsAllowed(background, PrivilegedOperation.QuarantinePurge));
        Assert.Contains("interactiva", PrivilegedOperationPolicy.DenialReason(background, PrivilegedOperation.QuarantinePurge));
    }

    [Fact]
    public void IdentidadSinSidNiPidSeRechaza()
    {
        Assert.False(PrivilegedOperationPolicy.IsAllowed(Elevated() with { Sid = "" }, PrivilegedOperation.PolicyChange));
        Assert.False(PrivilegedOperationPolicy.IsAllowed(Elevated() with { ProcessId = 0 }, PrivilegedOperation.PolicyChange));
    }

    [Fact]
    public void IntegridadBajaNoAutorizaAunqueElTokenSeaDeAdministrador()
    {
        var low = Elevated() with { IntegrityRid = NativeClientIdentity.LowIntegrityRid };
        Assert.False(PrivilegedOperationPolicy.IsAllowed(low, PrivilegedOperation.QuarantinePurge));
        Assert.Contains("administrativo", PrivilegedOperationPolicy.DenialReason(low, PrivilegedOperation.QuarantinePurge));
    }

    [Fact]
    public void ElPayloadNoPuedeSuplantarLaIdentidadDelCliente()
    {
        var properties = typeof(IpcRequest).GetProperties().Select(p => p.Name).ToArray();
        Assert.Equal(new[] { "Operation", "Payload" }, properties.OrderBy(n => n).ToArray());
        Assert.DoesNotContain("Sid", properties);
        Assert.DoesNotContain("ProcessId", properties);
        Assert.DoesNotContain("IntegrityRid", properties);
        Assert.DoesNotContain("Elevation", properties);
    }

    [Fact]
    public void SolicitudValidaSoloConOperacionConocidaYPayloadObjeto()
    {
        var request = new IpcRequest
        {
            Operation = PrivilegedOperation.FirewallAddRule,
            Payload = JsonSerializer.SerializeToElement(new { spec = new { name = "AEGIS Guard - TEST" } })
        };
        Assert.True(request.TryValidate(out var error));
        Assert.Equal(string.Empty, error);
    }

    [Fact]
    public void SolicitudConPayloadNoObjetoSeRechaza()
    {
        var request = new IpcRequest
        {
            Operation = PrivilegedOperation.PolicyChange,
            Payload = JsonSerializer.SerializeToElement(new[] { 1, 2, 3 })
        };
        Assert.False(request.TryValidate(out var error));
        Assert.Contains("objeto", error);
    }

    [Fact]
    public void NombreDeTuberiaDependeDelSidYEsEstable()
    {
        var first = PrivilegedIpcEndpoints.PipeNameForSid("S-1-5-21-100-200-300-1001");
        var second = PrivilegedIpcEndpoints.PipeNameForSid("S-1-5-21-100-200-300-1001");
        var other = PrivilegedIpcEndpoints.PipeNameForSid("S-1-5-21-100-200-300-1002");
        Assert.Equal(first, second);
        Assert.NotEqual(first, other);
        Assert.StartsWith("aegisguard-", first);
        Assert.EndsWith("-privileged", first);
    }

    [Fact]
    public void ElSidAutorizadoFijaElNombreInclusoSiLaElevacionUsaOtraCuenta()
    {
        const string installedSid = "S-1-5-21-100-200-300-1001";
        var previous = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        try
        {
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", installedSid);
            Assert.Equal(
                PrivilegedIpcEndpoints.PipeNameForSid(installedSid),
                AegisIpcNames.PrivilegedPipeForAuthorizedUser());
            Assert.Equal(
                AegisIpcNames.PrivilegedPipe(installedSid),
                PrivilegedIpcEndpoints.PipeNameForCurrentUser());
        }
        finally
        {
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", previous);
        }
    }

    [Fact]
    public void UnSidDistintoDelInstaladoNoEstaAutorizado()
    {
        const string installed = "S-1-5-21-100-200-300-1001";
        Assert.True(PrivilegedOperationPolicy.IsAuthorizedSid(Elevated(), installed));
        Assert.False(PrivilegedOperationPolicy.IsAuthorizedSid(Elevated() with { Sid = "S-1-5-21-9" }, installed));
        Assert.False(PrivilegedOperationPolicy.IsAuthorizedSid(Elevated(), string.Empty));
    }

    [Fact]
    public void LaDaclDelPipeNoConcedeAccesoATodosLosUsuariosInteractivos()
    {
        const string installed = "S-1-5-21-100-200-300-1001";
        var sddl = PrivilegedIpcServer.BuildSecurity(installed).GetSecurityDescriptorSddlForm(
            AccessControlSections.Access);
        var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null).Value;
        Assert.DoesNotContain(interactive, sddl, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(installed, sddl, StringComparison.OrdinalIgnoreCase);
        // SDDL usa el alias SY para LOCAL SYSTEM, no el SID literal.
        Assert.Contains(";SY)", sddl, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ElSidDeLaInstalacionEsObligatorioParaAbrirElCanal()
    {
        var previous = Environment.GetEnvironmentVariable("AEGIS_UI_USER_SID");
        try
        {
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", null);
            Assert.Throws<InvalidOperationException>(AegisIpcNames.RequireConfiguredAuthorizedSid);
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", "no-es-un-sid");
            Assert.Throws<InvalidOperationException>(AegisIpcNames.RequireConfiguredAuthorizedSid);
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", "S-1-5-21-100-200-300-1001");
            Assert.Equal("S-1-5-21-100-200-300-1001", AegisIpcNames.RequireConfiguredAuthorizedSid());
        }
        finally
        {
            Environment.SetEnvironmentVariable("AEGIS_UI_USER_SID", previous);
        }
    }

    [Fact]
    public void ElAnalisisNoAceptaRutasDelEstadoNiDelSistema()
    {
        var root = Path.Combine(Path.GetTempPath(), "aegis-scan-policy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var sample = Path.Combine(root, "sample.txt");
            File.WriteAllText(sample, "inocuo");
            Assert.True(ScanPathPolicy.IsAllowed(sample, new[] { root }, out var error));
            Assert.Equal(string.Empty, error);

            var dataFile = Path.Combine(AegisPaths.DataRoot, "config.json");
            Assert.False(ScanPathPolicy.IsAllowed(dataFile, new[] { root }, out error));
            Assert.Contains("estado", error);

            var systemFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "system.ini");
            Assert.False(ScanPathPolicy.IsAllowed(systemFile, new[] { root }, out error));
            Assert.Contains("protegida", error);

            Assert.False(ScanPathPolicy.IsAllowed(Path.Combine(root, "*.txt"), new[] { root }, out error));
            Assert.Contains("comodines", error);
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }
}

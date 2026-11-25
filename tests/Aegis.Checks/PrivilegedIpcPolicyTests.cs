using System.Text.Json;
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

    [Fact]
    public void TodasLasOperacionesSensiblesExigenClearanceElevada()
    {
        foreach (PrivilegedOperation operation in Enum.GetValues<PrivilegedOperation>())
        {
            Assert.Equal(ClientClearance.Elevated, PrivilegedOperationPolicy.Required(operation));
            Assert.False(PrivilegedOperationPolicy.IsAllowed(Standard(), operation));
            Assert.True(PrivilegedOperationPolicy.IsAllowed(Elevated(), operation));
        }
    }

    [Fact]
    public void TokenLimitadoNoAutorizaAunqueElSidSeaAdministrador()
    {
        var limited = Elevated() with { Elevation = TokenElevationType.Limited };
        foreach (PrivilegedOperation operation in Enum.GetValues<PrivilegedOperation>())
            Assert.False(PrivilegedOperationPolicy.IsAllowed(limited, operation));
        Assert.Contains("limitado", PrivilegedOperationPolicy.DenialReason(limited, PrivilegedOperation.PolicyChange));
    }

    [Fact]
    public void IntegridadMediaNoAutorizaAunqueLaElevacionSeaCompleta()
    {
        var medium = Elevated() with { IntegrityRid = NativeClientIdentity.MediumIntegrityRid };
        Assert.False(PrivilegedOperationPolicy.IsAllowed(medium, PrivilegedOperation.FirewallAddRule));
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
}

using Aegis.Core;

namespace Aegis.Tests;

public sealed class QuarantineTests
{
    [Fact]
    public void UnsafePathsAreRejectedBeforeAnyWrite()
    {
        Assert.False(PathPolicy.IsQuarantineSafe("ruta-relativa"));
        Assert.False(PathPolicy.IsQuarantineSafe(@"C:\"));
        if (OperatingSystem.IsWindows())
            Assert.False(PathPolicy.IsQuarantineSafe(@"C:\Program Files\Aegis\app.dll"));
    }
}

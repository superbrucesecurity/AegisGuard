using Aegis.Core;

namespace Aegis.Tests;

public sealed class TelemetryUtilsTests
{
    [Theory]
    [InlineData(16777343, "127.0.0.1")]
    [InlineData(234924224, "192.168.0.14")]
    [InlineData(-83886097, "239.255.255.250")]
    public void NetworkPayloadNumbersAreLittleEndian(long raw, string expected) =>
        Assert.Equal(expected, TelemetryAddress.Normalize(raw.ToString()));

    [Theory]
    [InlineData("127.0.0.1", "127.0.0.1")]
    [InlineData("::1", "::1")]
    [InlineData("", null)]
    public void TextAddressesStayUnchanged(string? raw, string? expected) =>
        Assert.Equal(expected, TelemetryAddress.Normalize(raw));

    [Theory]
    [InlineData(56944, "56944")]
    [InlineData(-1, null)]
    [InlineData(70000, null)]
    [InlineData("443", "443")]
    public void InvalidPortsAreRejectedInsteadOfWrapping(object raw, string? expected) =>
        Assert.Equal(expected, TelemetryAddress.NormalizePort(raw));

    [Theory]
    [InlineData(" 1.2.3.4 ", "1.2.3.4")]
    [InlineData("1.2.3.4:443", "1.2.3.4")]
    public void AddressesAreTrimmedAndSplitFromPort(string raw, string expected) =>
        Assert.Equal(expected, TelemetryAddress.Normalize(raw));

    [Fact]
    public void DuplicateWindowSuppressesRepeatedKeys()
    {
        var dedupe = new EventDeduplicator();
        Assert.False(dedupe.IsDuplicate("net:127.0.0.1:443:TCP", 10_000));
        Assert.True(dedupe.IsDuplicate("net:127.0.0.1:443:TCP", 10_000));
        Assert.False(dedupe.IsDuplicate("net:127.0.0.1:80:TCP", 10_000));
    }

    [Fact]
    public void DuplicateWindowExpires()
    {
        var dedupe = new EventDeduplicator();
        // TickCount64 se actualiza cada ~15 ms en Windows.
        Assert.False(dedupe.IsDuplicate("file:C:\\tmp\\a.exe", 1));
        Thread.Sleep(50);
        Assert.False(dedupe.IsDuplicate("file:C:\\tmp\\a.exe", 1));
    }
}

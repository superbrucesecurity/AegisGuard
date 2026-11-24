using System.Net;
using System.Net.Http.Json;
using Aegis.Core;

namespace Aegis.Tests;

public sealed class LiquidGatewayClientTests
{
    [Fact]
    public async Task ValidResponseIsAcceptedAndCached()
    {
        const string json = """
            {"model":"d1.2-ultra","choiceLabel":"SUSPICIOUS","clean":0.2,"suspicious":0.7,
             "malicious":0.1,"confidence":0.8,"severityScore":1,"isValid":true,
             "latencyMs":12,"requestId":"r1"}
            """;
        var handler = new FakeHandler([new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        }]);
        var client = new LiquidGatewayClient("http://127.0.0.1:8790", "clave-de-prueba", handler);
        var request = Request("r1");

        var first = await client.ClassifyAsync(request);
        var second = await client.ClassifyAsync(request);

        Assert.True(first.IsValid);
        Assert.Equal("SUSPICIOUS", first.ChoiceLabel);
        Assert.Equal(0.7, first.Suspicious, 3);
        Assert.Equal(1, client.Calls);
        Assert.Equal(1, client.CacheHits);
        Assert.Equal("clave-de-prueba", handler.LastKey);
        Assert.Equal("/v1/classify", handler.LastPath);
    }

    [Fact]
    public async Task OutOfRangeProbabilitiesAreRejected()
    {
        const string json = """
            {"model":"d1.2-ultra","choiceLabel":"MALICIOUS","clean":0.9,"suspicious":0.9,
             "malicious":0.9,"confidence":0.9,"severityScore":3,"isValid":true}
            """;
        var handler = new FakeHandler(Enumerable.Repeat(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
        }, 3));
        var client = new LiquidGatewayClient("http://127.0.0.1:8790", "clave-de-prueba", handler);

        var result = await client.ClassifyAsync(Request("r2"));
        Assert.False(result.IsValid);
        Assert.Contains("fuera de rango", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CircuitOpensAfterRepeatedFailures()
    {
        var handler = new FakeHandler([new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)]);
        var client = new LiquidGatewayClient("http://127.0.0.1:8790", "clave-de-prueba", handler);

        await client.ClassifyAsync(Request("a"));
        await client.ClassifyAsync(Request("b"));
        var third = await client.ClassifyAsync(Request("c"));
        var fourth = await client.ClassifyAsync(Request("d"));

        Assert.False(third.IsValid);
        Assert.Contains("circuit-open", fourth.Error ?? string.Empty, StringComparison.Ordinal);
    }

    private static CloudClassificationRequest Request(string id) => new()
    {
        RequestId = id,
        Sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(id))).ToLowerInvariant(),
        FileType = "txt",
        Signature = SignatureStatus.NotApplicable,
        EventKind = "ManualScan",
        BehaviorFlags = ["connectivity_test"],
        Reputation = 0.5
    };

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses;
        public string? LastKey { get; private set; }
        public string? LastPath { get; private set; }

        public FakeHandler(IEnumerable<HttpResponseMessage> responses) => _responses = new(responses);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastKey = request.Headers.TryGetValues("X-Aegis-Key", out var values) ? values.FirstOrDefault() : null;
            LastPath = request.RequestUri?.AbsolutePath;
            return Task.FromResult(_responses.Count > 0 ? _responses.Dequeue() : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
        }
    }
}

using System.Collections.Concurrent;
using Aegis.Core;

namespace Aegis.Service;

public sealed class DetectionPipeline
{
    private readonly FileInspector _inspector = new();
    private readonly DecisionEngine _decision = new();
    private readonly YaraLiteEngine _yara;
    private readonly ThreatIntel _intel;
    private readonly IAiClassifier _ai;
    private readonly QuarantineManager _quarantine;
    private readonly EventStore _store;
    private readonly RuntimeState _state;
    private readonly FirewallManager _firewall;
    private readonly RansomwareCanary _canary;
    private readonly ILogger<DetectionPipeline> _logger;
    private readonly ConcurrentDictionary<string, int> _learnedConnections = new();

    public DetectionPipeline(
        YaraLiteEngine yara,
        ThreatIntel intel,
        IAiClassifier ai,
        QuarantineManager quarantine,
        EventStore store,
        RuntimeState state,
        FirewallManager firewall,
        RansomwareCanary canary,
        ILogger<DetectionPipeline> logger)
    {
        _yara = yara;
        _intel = intel;
        _ai = ai;
        _quarantine = quarantine;
        _store = store;
        _state = state;
        _firewall = firewall;
        _canary = canary;
        _logger = logger;
    }

    public IReadOnlyList<LearnedConnection> LearnedConnections =>
        _learnedConnections.Select(x => new LearnedConnection { Endpoint = x.Key, Observations = x.Value })
            .OrderByDescending(x => x.Observations).Take(50).ToList();

    public async Task<ThreatRecord> ProcessAsync(Observation observation, CancellationToken ct = default)
    {
        var policy = _state.GetPolicy();
        var ruleMatches = new List<RuleMatch>(observation.RuleMatches);
        await EnrichAsync(observation, ruleMatches, ct).ConfigureAwait(false);

        var local = _decision.Assess(observation, ruleMatches, _intel.SnapshotHashes());
        var ai = await ClassifyIfNeededAsync(observation, local, ruleMatches, policy, ct).ConfigureAwait(false);
        var decision = _decision.Decide(observation, local, ai, policy);

        await _store.AppendAsync(observation).ConfigureAwait(false);

        var threat = new ThreatRecord { Observation = observation, Decision = decision };
        await ApplyRemediationAsync(threat, policy, ct).ConfigureAwait(false);
        await _store.AppendAsync(threat).ConfigureAwait(false);
        _state.Record(decision);

        if (decision.Severity >= Severity.High)
            _logger.LogInformation("Amenaza {Severity}: {Subject} -> {Verdict} (riesgo {Risk})", decision.Severity, observation.Subject, decision.Verdict, decision.Risk);

        return threat;
    }

    public async Task<ThreatRecord> ScanPathAsync(string path, CancellationToken ct = default)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("No se encontró el fichero", path);
        var observation = new Observation
        {
            Kind = EventKind.ManualScan,
            Subject = Path.GetFullPath(path),
            FileExtension = Path.GetExtension(path),
            Source = "manual"
        };
        return await ProcessAsync(observation, ct).ConfigureAwait(false);
    }

    private async Task EnrichAsync(Observation o, List<RuleMatch> matches, CancellationToken ct)
    {
        var isFileEvent = o.Kind is EventKind.FileCreated or EventKind.FileModified or EventKind.ManualScan;
        if (isFileEvent && File.Exists(o.Subject))
        {
            try
            {
                var (hash, length, eicar) = await _inspector.HashAsync(o.Subject, ct).ConfigureAwait(false);
                o.Sha256 = hash;
                o.FileSize = length;
                o.FileExtension ??= Path.GetExtension(o.Subject);
                o.Signature = _inspector.VerifySignature(o.Subject);

                if (eicar)
                {
                    matches.Add(new RuleMatch
                    {
                        RuleId = "EICAR-STANDARD-TEST",
                        Name = "Fichero de prueba EICAR",
                        Severity = Severity.Critical,
                        Evidence = ["firma EICAR"]
                    });
                }

                var yaraMatches = await _yara.ScanFileAsync(o.Subject, hash, ct).ConfigureAwait(false);
                matches.AddRange(yaraMatches);

                if (_canary.IsCanary(o.Subject) && _canary.WasModified(o.Subject))
                    o.BehaviorFlags.Add("ransomware_canary_modified");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogDebug(ex, "No se pudo inspeccionar {Path}", o.Subject);
            }
        }

        if (o.Kind == EventKind.DnsQuery && _intel.IsMaliciousDomain(o.Subject))
            o.BehaviorFlags.Add("c2_beacon");

        if (o.Kind == EventKind.NetworkConnection)
        {
            if (_intel.IsMaliciousIp(o.RemoteAddress)) o.BehaviorFlags.Add("c2_beacon");
            if (!string.IsNullOrWhiteSpace(o.Subject) &&
                o.Subject.Contains(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
                o.BehaviorFlags.Add("temp_execution");
        }

        if (o.Kind == EventKind.ProcessStarted)
        {
            if (!string.IsNullOrWhiteSpace(o.Subject) && o.Subject.Contains(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
                o.BehaviorFlags.Add("temp_execution");
            if (!string.IsNullOrWhiteSpace(o.ParentProcess) &&
                o.ParentProcess.Contains("WINWORD", StringComparison.OrdinalIgnoreCase) ||
                (!string.IsNullOrWhiteSpace(o.ParentProcess) && o.ParentProcess.Contains("EXCEL", StringComparison.OrdinalIgnoreCase)))
                o.BehaviorFlags.Add("unusual_parent");
        }
    }

    private async Task<AiClassification> ClassifyIfNeededAsync(
        Observation o, LocalAssessment local, List<RuleMatch> matches, PolicySettings policy, CancellationToken ct)
    {
        if (!policy.AiEnabled)
            return new AiClassification { IsValid = false, Error = "IA desactivada por política" };

        // Solo se envían a la nube eventos con indicios locales significativos:
        // Evita coste y exposición innecesaria de telemetría cotidiana.
        var needsAi = local.Score >= 20 || o.BehaviorFlags.Count > 0 ||
                      o.Kind is EventKind.ManualScan or EventKind.PersistenceChanged;
        if (!needsAi)
            return new AiClassification { IsValid = false, Error = "no enviado: sin indicios locales" };

        var request = new CloudClassificationRequest
        {
            RequestId = o.Id,
            Sha256 = o.Sha256 ?? SHA256Placeholder(o.Subject),
            FileType = o.FileExtension?.TrimStart('.').ToLowerInvariant() ?? o.Kind.ToString(),
            SizeBucket = o.FileSize / 4096,
            Signature = o.Signature,
            Reputation = o.Reputation,
            BehaviorFlags = o.BehaviorFlags.Take(16).ToList(),
            RuleIds = matches.Select(x => x.RuleId).Take(16).ToList(),
            EventKind = o.Kind.ToString()
        };

        var result = await _ai.ClassifyAsync(request, ct).ConfigureAwait(false);
        _state.AiReachable = result.IsValid;
        return result;
    }

    private async Task ApplyRemediationAsync(ThreatRecord threat, PolicySettings policy, CancellationToken ct)
    {
        var o = threat.Observation;
        var d = threat.Decision;
        var actions = new List<string>();

        if (d.Verdict == Verdict.Quarantine && policy.AutoQuarantine &&
            o.Kind is EventKind.FileCreated or EventKind.FileModified or EventKind.ManualScan &&
            PathPolicy.IsQuarantineSafe(o.Subject) && File.Exists(o.Subject))
        {
            try
            {
                var item = await _quarantine.QuarantineAsync(o.Subject, string.Join("; ", d.Reasons.Take(3)), threat.Id, o.Sha256 ?? string.Empty, ct).ConfigureAwait(false);
                actions.Add($"cuarentena:{item.Id}");
            }
            catch (Exception ex)
            {
                actions.Add($"cuarentena-error:{ex.Message}");
                _logger.LogWarning(ex, "No se pudo poner en cuarentena {Path}", o.Subject);
            }
        }

        if (d.Verdict is Verdict.Block or Verdict.Quarantine &&
            policy.AutoBlockNetwork && !string.IsNullOrWhiteSpace(o.RemoteAddress))
        {
            var spec = new FirewallRuleSpec
            {
                Name = _firewall.BuildRuleName(new FirewallRuleSpec
                {
                    Block = true,
                    ApplicationPath = File.Exists(o.Subject) ? o.Subject : null,
                    RemoteAddresses = o.RemoteAddress,
                    RemotePort = int.TryParse(o.RemotePort, out var port) ? port : null
                }),
                Block = true,
                ApplicationPath = File.Exists(o.Subject) ? o.Subject : null,
                RemoteAddresses = o.RemoteAddress,
                RemotePort = int.TryParse(o.RemotePort, out var port2) ? port2 : null,
                Description = $"AEGIS Guard - {threat.Id} - riesgo {d.Risk}"
            };
            try
            {
                if (_firewall.AddRule(spec))
                {
                    Interlocked.Increment(ref _state.BlockedNetworkTotal);
                    actions.Add("firewall-bloqueado");
                }
            }
            catch (Exception ex)
            {
                actions.Add($"firewall-error:{ex.Message}");
                _logger.LogWarning(ex, "No se pudo crear regla de firewall");
            }
        }

        if (policy.LearningMode && o.Kind == EventKind.NetworkConnection && !string.IsNullOrWhiteSpace(o.RemoteAddress))
        {
            var key = $"{Path.GetFileName(o.Subject)} -> {o.RemoteAddress}:{o.RemotePort}";
            _learnedConnections.AddOrUpdate(key, 1, (_, count) => Math.Min(count + 1, 9999));
        }

        if (actions.Count > 0)
        {
            threat.Remediated = actions.Any(x => x.StartsWith("cuarentena:", StringComparison.OrdinalIgnoreCase) || x == "firewall-bloqueado");
            threat.RemediationDetail = string.Join(", ", actions);
        }
    }

    private static string SHA256Placeholder(string subject)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(subject.ToLowerInvariant());
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
    }
}

public sealed class LearnedConnection
{
    public string Endpoint { get; set; } = string.Empty;
    public int Observations { get; set; }
}

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using Aegis.Core;

namespace Aegis.Service;

public sealed class DetectionPipeline
{
    private readonly FileInspector _inspector = new();
    private readonly DecisionEngine _decision = new();
    private readonly PeInspector _pe = new();
    private readonly ArchiveInspector _archive = new();
    private readonly ScriptInspector _script = new();
    private readonly MacroInspector _macro = new();
    private readonly YaraLiteEngine _yara;
    private readonly ThreatIntel _intel;
    private readonly QuarantineManager _quarantine;
    private readonly EventStore _store;
    private readonly RuntimeState _state;
    private readonly LocalReputation _reputation;
    private readonly FirewallManager _firewall;
    private readonly RansomwareCanary _canary;
    private readonly CorrelationEngine _correlation;
    private readonly ILogger<DetectionPipeline> _logger;
    private readonly ConcurrentDictionary<string, int> _learnedConnections = new();

    public DetectionPipeline(
        YaraLiteEngine yara,
        ThreatIntel intel,
        QuarantineManager quarantine,
        EventStore store,
        RuntimeState state,
        LocalReputation reputation,
        FirewallManager firewall,
        RansomwareCanary canary,
        ILogger<DetectionPipeline> logger,
        CorrelationEngine? correlation = null)
    {
        _correlation = correlation ?? new CorrelationEngine();
        _yara = yara;
        _intel = intel;
        _quarantine = quarantine;
        _store = store;
        _state = state;
        _reputation = reputation;
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
        var decision = await EvaluateAsync(observation, recordCorrelation: true, ct).ConfigureAwait(false);

        await _store.AppendAsync(observation).ConfigureAwait(false);

        var threat = new ThreatRecord { Observation = observation, Decision = decision };
        await ApplyRemediationAsync(threat, policy, ct).ConfigureAwait(false);
        await _store.AppendAsync(threat).ConfigureAwait(false);
        _state.Record(decision);
        _reputation.Record(observation.Sha256 ?? observation.Subject,
            decision.Verdict is Verdict.Block or Verdict.Quarantine);
        await _reputation.SaveAsync(ct).ConfigureAwait(false);

        if (decision.Severity >= Severity.High)
            _logger.LogInformation("Amenaza {Severity}: {Subject} -> {Verdict} (riesgo {Risk})", decision.Severity, observation.Subject, decision.Verdict, decision.Risk);

        return threat;
    }

    /// <summary>
    /// Evalúa una observación con el motor real, sin persistirla ni aplicar
    /// remediación. La usa la prueba EICAR para verificar la detección sin
    /// contaminar el historial ni poner en cuarentena el fichero de prueba.
    /// </summary>
    private async Task<DecisionResult> EvaluateAsync(
        Observation observation, bool recordCorrelation, CancellationToken ct)
    {
        var ruleMatches = new List<RuleMatch>(observation.RuleMatches);
        await EnrichAsync(observation, ruleMatches, ct).ConfigureAwait(false);
        // La observación persistida (y la UI) debe mostrar la evidencia real
        // producida por todos los analizadores, no solo la del watcher.
        observation.RuleMatches = [.. ruleMatches];
        // Las variantes de solo evaluación (escaneo manual y EICAR) no alimentan
        // la memoria de correlación: un usuario no puede influir en eventos futuros.
        var correlations = recordCorrelation
            ? _correlation.Observe(observation)
            : [];
        var local = _decision.Assess(observation, ruleMatches, _intel.SnapshotHashes(), correlations);
        return _decision.Decide(observation, local, _state.GetPolicy());
    }

    /// <summary>
    /// Escribe la muestra EICAR en el directorio de estado del producto, la
    /// analiza con el mismo motor que cualquier fichero y la elimina. Si otro
    /// producto de seguridad retira el archivo antes del análisis se informa
    /// explícitamente: nunca se presenta como "no detectado" ni se desactiva
    /// ese producto.
    /// </summary>
    public async Task<SelfTestResult> SelfTestEicarAsync(CancellationToken ct = default)
    {
        var directory = Path.Combine(AegisPaths.DataRoot, "selftest");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"eicar-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllBytesAsync(path, FileInspector.EicarSampleBytes, ct).ConfigureAwait(false);
            // Verificar la muestra antes de analizarla permite distinguir un
            // bloqueo externo de un fallo del motor.
            var written = await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
            if (!FileInspector.ContainsEicarSample(written))
                return new SelfTestResult
                {
                    FileBlockedExternally = true,
                    Detail = "Otro producto de seguridad alteró la muestra antes del análisis. No desactive ese producto."
                };

            var observation = new Observation
            {
                Kind = EventKind.ManualScan,
                Subject = path,
                FileExtension = ".txt",
                Source = "selftest"
            };
            var decision = await EvaluateAsync(observation, recordCorrelation: false, ct).ConfigureAwait(false);
            var detected = decision.Local.HasVerifiedIndicator && decision.Verdict != Verdict.Allow;
            if (!detected && decision.Local.EvidenceCount == 0)
                return new SelfTestResult
                {
                    FileBlockedExternally = true,
                    Detail = "La muestra desapareció antes de ser inspeccionada; compruebe el informe de su antivirus. No se desarmó el motor."
                };
            return new SelfTestResult
            {
                Detected = detected,
                Verdict = decision.Verdict.ToString(),
                Risk = decision.Risk,
                Reasons = decision.Reasons,
                Detail = detected
                    ? "Muestra analizada por el motor local; no se guardó en el historial."
                    : "El motor no reconoció la muestra; revise las reglas instaladas."
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new SelfTestResult
            {
                FileBlockedExternally = true,
                Detail = $"No se pudo analizar la muestra: {ex.Message}. Compruebe el informe de su producto de seguridad; no lo desactive."
            };
        }
        finally
        {
            try { File.Delete(path); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _logger.LogDebug(ex, "No se pudo eliminar la muestra EICAR {Path}", path);
            }
        }
    }

    public async Task<ThreatRecord> ScanPathAsync(string path, CancellationToken ct = default) =>
        await ProcessAsync(ManualObservation(path), ct).ConfigureAwait(false);

    /// <summary>
    /// Analiza un fichero con el motor real pero no persiste el resultado, no
    /// actualiza contadores ni reputación y no aplica remediación. Es la única
    /// variante permitida desde HTTP: una petición de lectura del navegador no
    /// debe poder poner en cuarentena ni crear reglas de firewall.
    /// </summary>
    public async Task<ThreatRecord> ScanPathReadOnlyAsync(string path, CancellationToken ct = default)
    {
        var elapsed = Stopwatch.StartNew();
        var observation = ManualObservation(path);
        var decision = await EvaluateAsync(observation, recordCorrelation: false, ct).ConfigureAwait(false);
        var threat = new ThreatRecord { Observation = observation, Decision = decision };
        // El informe es una proyección en memoria de la evidencia ya calculada.
        // No escribe historial, reputación ni contadores.
        threat.Report = ScanReportBuilder.Build(threat, elapsed.ElapsedMilliseconds);
        return threat;
    }

    private static Observation ManualObservation(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("No se encontró el fichero", path);
        return new Observation
        {
            Kind = EventKind.ManualScan,
            Subject = Path.GetFullPath(path),
            FileExtension = Path.GetExtension(path),
            Source = "manual"
        };
    }

    private async Task EnrichAsync(Observation o, List<RuleMatch> matches, CancellationToken ct)
    {
        // ProcessStarted también se enriquece: ETW observa la imagen y el motor
        // debe calcular hash, firma y reglas sobre ella, no solo registrar el PID.
        var isFileEvent = o.Kind is EventKind.FileCreated or EventKind.FileModified or
            EventKind.ManualScan or EventKind.ProcessStarted;
        if (isFileEvent && File.Exists(o.Subject))
        {
            try
            {
                var inspection = await _inspector.InspectAsync(o.Subject, ct: ct).ConfigureAwait(false);
                o.Sha256 = inspection.Sha256;
                o.FileSize = inspection.Length;
                o.FileExtension ??= Path.GetExtension(o.Subject);
                o.Signature = _inspector.VerifySignature(o.Subject);

                if (inspection.Eicar)
                {
                    matches.Add(new RuleMatch
                    {
                        RuleId = "EICAR-STANDARD-TEST",
                        Name = "Fichero de prueba EICAR",
                        Severity = Severity.Critical,
                        Evidence = ["firma EICAR"]
                    });
                }

                if (inspection.Truncated)
                {
                    // Un fichero por encima del tope no se presenta como limpio:
                    // se registra una razón verificable de análisis incompleto.
                    matches.Add(new RuleMatch
                    {
                        RuleId = "ANALYSIS-TRUNCATED",
                        Name = "Análisis limitado por tamaño",
                        Severity = Severity.Info,
                        Evidence = [$"{inspection.Length} bytes > {AnalysisLimits.MaxScanBytes} bytes"]
                    });
                }

                var yaraMatches = await _yara.ScanFileAsync(o.Subject, inspection.Sha256, ct).ConfigureAwait(false);
                matches.AddRange(yaraMatches);

                var ext = NormalizeExtension(o.FileExtension ?? Path.GetExtension(o.Subject));
                if (ext is ".exe" or ".dll" or ".sys" or ".scr" or ".com" or ".cpl" or ".ocx" or ".drv")
                    matches.AddRange(_pe.Analyze(inspection.Prefix, inspection.Length));

                if (ext is ".ps1" or ".psm1" or ".bat" or ".cmd" or ".js" or ".jse" or ".vbs" or ".hta")
                    matches.AddRange(_script.Analyze(inspection.Prefix, ext));

                var archiveExt = ext is ".zip" or ".jar" or ".gz" or ".tgz" or ".tar";
                var macroExt = ext is ".doc" or ".xls" or ".ppt" or ".docx" or ".xlsx" or ".pptx" or
                    ".docm" or ".xlsm" or ".pptm";
                byte[]? container = null;
                if (archiveExt || (macroExt && ext is not (".doc" or ".xls" or ".ppt")))
                {
                    var read = await _inspector.ReadBytesAsync(o.Subject, ct: ct).ConfigureAwait(false);
                    container = read.bytes;
                    if (read.truncated)
                        matches.Add(new RuleMatch
                        {
                            RuleId = "CONTAINER-INCOMPLETE",
                            Name = "Contenedor no analizado por completo",
                            Severity = Severity.Info,
                            Category = archiveExt ? "archive" : "macro",
                            Evidence = [$"{read.length} bytes > {AnalysisLimits.MaxArchiveBytes} bytes"]
                        });
                }

                if (archiveExt && container is not null)
                    matches.AddRange(await _archive.AnalyzeAsync(container, ext, ct).ConfigureAwait(false));

                if (macroExt)
                    matches.AddRange(await _macro.AnalyzeAsync(container ?? inspection.Prefix, ext, ct)
                        .ConfigureAwait(false));

                // La firma y los analizadores abren la ruta por separado. Volver a
                // calcular el hash impide decidir sobre un contenido que cambió.
                var confirmed = await _inspector.HashAsync(o.Subject, ct).ConfigureAwait(false);
                if (!string.Equals(confirmed.sha256, inspection.Sha256, StringComparison.OrdinalIgnoreCase))
                    matches.Add(new RuleMatch
                    {
                        RuleId = "ANALYSIS-CONTENT-CHANGED",
                        Name = "El fichero cambió durante el análisis",
                        Severity = Severity.High,
                        Category = "integrity",
                        Evidence = [$"inicial={inspection.Sha256}", $"final={confirmed.sha256}"]
                    });

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
            var parent = o.ParentProcess;
            if (!string.IsNullOrWhiteSpace(parent) &&
                (parent.Contains("WINWORD", StringComparison.OrdinalIgnoreCase) ||
                 parent.Contains("EXCEL", StringComparison.OrdinalIgnoreCase)))
                o.BehaviorFlags.Add("unusual_parent");

            // Un PID puede reutilizarse: si el proceso actual no coincide con la
            // hora de creación observada, la atribución no es fiable y se marca.
            if (int.TryParse(o.ProcessId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid) && pid > 0 &&
                o.Metadata.TryGetValue("processCreateTimeUtc", out var raw) &&
                DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var reported))
            {
                try
                {
                    using var process = Process.GetProcessById(pid);
                    var actual = new DateTimeOffset(process.StartTime.ToUniversalTime());
                    if (Math.Abs((actual - reported).TotalSeconds) > 2)
                        o.BehaviorFlags.Add("pid_reuse_suspected");
                }
                catch (ArgumentException)
                {
                    // El proceso ya terminó: no es prueba de reutilización.
                }
            }
        }

        // La reputación se lee aquí para que los eventos de fichero ya tengan hash.
        o.Reputation = _reputation.Get(o.Sha256 ?? o.Subject);
    }

    private static string NormalizeExtension(string? extension)
    {
        if (string.IsNullOrWhiteSpace(extension)) return string.Empty;
        var value = extension.Trim();
        if (!value.StartsWith('.')) value = "." + value;
        return value.ToLowerInvariant();
    }

    private async Task ApplyRemediationAsync(ThreatRecord threat, PolicySettings policy, CancellationToken ct)
    {
        var o = threat.Observation;
        var d = threat.Decision;
        var actions = new List<string>();

        // Se resuelve antes de la cuarentena: si el archivo se mueve primero,
        // la regla WFP quedaría solo por IP/puerto y perdería la aplicación.
        var applicationPath = (o.Kind is EventKind.ProcessStarted or EventKind.NetworkConnection or
            EventKind.FileCreated or EventKind.FileModified or EventKind.ManualScan) &&
            !string.IsNullOrWhiteSpace(o.Subject) && File.Exists(o.Subject)
                ? Path.GetFullPath(o.Subject)
                : null;

        if (RemediationPolicy.ShouldQuarantine(d, policy) &&
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

        if (RemediationPolicy.ShouldBlockNetwork(d, policy) &&
            !string.IsNullOrWhiteSpace(o.RemoteAddress))
        {
            var spec = new FirewallRuleSpec
            {
                Block = true,
                ApplicationPath = applicationPath,
                RemoteAddresses = o.RemoteAddress,
                RemotePort = int.TryParse(o.RemotePort, out var port) ? port : null,
                Description = $"AEGIS Guard - {threat.Id} - riesgo {d.Risk}"
            };
            spec.Name = _firewall.BuildRuleName(spec);
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

        // En aprendizaje se conserva la decisión, pero se omite la acción
        // automática salvo que exista un indicio verificado localmente.
        if (policy.LearningMode && !d.Local.HasVerifiedIndicator &&
            d.Verdict is Verdict.Block or Verdict.Quarantine)
            actions.Add("modo-aprendizaje:sin acción automática");

        if (actions.Count > 0)
        {
            threat.Remediated = actions.Any(x => x.StartsWith("cuarentena:", StringComparison.OrdinalIgnoreCase) || x == "firewall-bloqueado");
            threat.RemediationDetail = string.Join(", ", actions);
        }
    }

}

public sealed class LearnedConnection
{
    public string Endpoint { get; set; } = string.Empty;
    public int Observations { get; set; }
}

namespace Aegis.Core;

/// <summary>
/// Reglas de decisión deterministas basadas únicamente en evidencia local:
/// hashes, reglas, firma, reputación y banderas observadas por el monitor.
/// El riesgo se calcula íntegramente en el equipo.
/// </summary>
public sealed class DecisionEngine
{
    public DecisionResult Decide(Observation observation, LocalAssessment local, PolicySettings policy)
    {
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(policy);

        policy.Validate();

        var risk = Math.Clamp(local.Score, 0, 100);
        var reasons = new List<string>();
        foreach (var c in local.Contributions.OrderByDescending(x => x.Weight).Take(4))
        {
            var evidence = string.IsNullOrWhiteSpace(c.Evidence) ? string.Empty : $" [{c.Evidence}]";
            reasons.Add($"{c.Source}: {c.Reason}{evidence} (+{c.Weight:0})");
        }

        var confidence = Math.Clamp(0.55 + local.EvidenceCount * 0.09, 0.55, 0.96);
        var verdict = VerdictFromRisk(risk, policy);

        // La evidencia crítica local manda por encima del modo aprendizaje y de
        // la configuración de cuarentena; si esta última está desactivada, se
        // degrada a bloqueo en lugar de permitir la amenaza.
        if (local.HasCriticalIndicator && observation.Kind is EventKind.FileCreated or EventKind.FileModified or EventKind.ManualScan)
        {
            if (policy.AutoQuarantine) verdict = Verdict.Quarantine;
            else if (verdict is Verdict.Allow or Verdict.Monitor) verdict = Verdict.Block;
        }

        var severity = SeverityFromRisk(risk, verdict);

        return new DecisionResult
        {
            ObservationId = observation.Id,
            Verdict = verdict,
            Severity = severity,
            Risk = Math.Round(risk, 2),
            Confidence = Math.Round(confidence, 2),
            Local = local,
            Reasons = reasons
        };
    }

    public LocalAssessment Assess(Observation observation, IReadOnlyList<RuleMatch> ruleMatches, IReadOnlySet<string> maliciousHashes)
    {
        var assessment = new LocalAssessment();
        void Add(string source, string reason, double weight, bool critical = false, bool verified = false, string evidence = "")
        {
            assessment.Score += weight;
            assessment.EvidenceCount++;
            assessment.Contributions.Add(new ScoreContribution
            {
                Source = source,
                Reason = reason,
                Weight = weight,
                Evidence = evidence
            });
            if (critical) assessment.HasCriticalIndicator = true;
            if (verified) assessment.HasVerifiedIndicator = true;
        }

        if (!string.IsNullOrWhiteSpace(observation.Sha256) && maliciousHashes.Contains(observation.Sha256))
            Add("hash", "Hash en lista de denegación", 100, critical: true, verified: true,
                evidence: observation.Sha256);

        // Una misma regla puede llegar desde el watcher y desde el escáner;
        // contarla dos veces inflaría el riesgo hasta una cuarentena espuria.
        foreach (var rule in ruleMatches.GroupBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).Select(g => g.First()))
        {
            var weight = rule.Severity switch
            {
                Severity.Critical => 65,
                Severity.High => 42,
                Severity.Medium => 22,
                Severity.Low => 9,
                _ => 2
            };
            var source = string.IsNullOrWhiteSpace(rule.Category) ? "yara" : rule.Category;
            Add(source, $"{rule.RuleId}: {rule.Name}", weight, rule.Severity == Severity.Critical,
                IsVerifiedRule(rule.RuleId), string.Join(", ", rule.Evidence));

        }

        if (observation.Signature == SignatureStatus.SignedUntrusted)
            Add("signature", "Firma digital no válida", 34);
        else if (observation.Signature == SignatureStatus.Unsigned && IsExecutable(observation))
            Add("signature", "Ejecutable sin firma digital", 12);
        else if (observation.Signature == SignatureStatus.ChainNotVerifiable)
            // Falta de caché de revocación: no es evidencia de malware. Solo
            // añade una señal débil y nunca crítica.
            Add("signature", "Cadena de certificados no verificable sin conexión", 8);

        if (observation.Reputation < 0.2)
            Add("reputation", "Reputación muy baja", 28);
        else if (observation.Reputation < 0.45)
            Add("reputation", "Reputación baja", 12);

        foreach (var flag in observation.BehaviorFlags.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            // Solo se puntúan las banderas que el monitor produce de verdad.
            // Una bandera desconocida no es evidencia: evita que un dato
            // manipulado o una capacidad no implementada infle el riesgo.
            var weight = flag switch
            {
                "ransomware_canary_modified" => 55,
                "canary_manifest_tampered" => 55,
                "c2_beacon" => 45,
                "persistence_registry" => 35,
                "unusual_parent" or "temp_execution" => 14,
                "file_renamed" => 8,
                "pid_reuse_suspected" => 35,
                "sensor_queue_saturated" => 40,
                _ => 0
            };
            if (weight == 0) continue;
            Add("behavior", flag, weight,
                flag is "ransomware_canary_modified" or "canary_manifest_tampered");
        }

        if (!string.IsNullOrWhiteSpace(observation.RemoteAddress) && IsPublicIp(observation.RemoteAddress))
            Add("network", "Conexión a IP pública", 6);

        assessment.Score = Math.Clamp(assessment.Score, 0, 100);
        return assessment;
    }

    private static bool IsVerifiedRule(string ruleId) =>
        ruleId.Equals("EICAR-STANDARD-TEST", StringComparison.OrdinalIgnoreCase) ||
        ruleId.Equals("EICAR_Standard_Test_File", StringComparison.OrdinalIgnoreCase);

    private static Verdict VerdictFromRisk(double risk, PolicySettings policy)
    {
        if (risk >= policy.QuarantineThreshold && policy.AutoQuarantine) return Verdict.Quarantine;
        if (risk >= policy.BlockThreshold) return Verdict.Block;
        if (risk >= policy.MonitorThreshold) return Verdict.Monitor;
        return Verdict.Allow;
    }

    private static Severity SeverityFromRisk(double risk, Verdict verdict)
    {
        if (verdict == Verdict.Quarantine || risk >= 85) return Severity.Critical;
        if (verdict == Verdict.Block || risk >= 65) return Severity.High;
        if (risk >= 40) return Severity.Medium;
        if (risk >= 20) return Severity.Low;
        return Severity.Info;
    }

    private static bool IsExecutable(Observation o)
    {
        var ext = o.FileExtension?.TrimStart('.').ToLowerInvariant();
        return ext is "exe" or "dll" or "sys" or "scr" or "com" or "msi" or "msp" or "msc" or
            "cpl" or "ocx" or "drv" or "ps1" or "bat" or "cmd" or "vbs" or "js" or "jse" or "hta";
    }

    private static bool IsPublicIp(string value)
    {
        if (!System.Net.IPAddress.TryParse(value.Trim(), out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (System.Net.IPAddress.IsLoopback(ip) || ip.Equals(System.Net.IPAddress.Any) ||
            ip.Equals(System.Net.IPAddress.IPv6Any)) return false;

        var b = ip.GetAddressBytes();
        if (b.Length == 16)
        {
            if ((b[0] & 0xfe) == 0xfc) return false;           // fc00::/7 ULA
            if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false; // fe80::/10
            if (b[0] == 0xff) return false;                   // multicast
            return true;
        }

        if (b[0] == 0 || b[0] >= 224 || b[0] == 127) return false;
        if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
            (b[0] == 192 && b[1] == 168)) return false;
        if (b[0] == 169 && b[1] == 254) return false;
        if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
        if (b[0] == 192 && b[1] == 0 && b[2] == 0) return false;
        if (b[0] == 192 && b[1] == 0 && b[2] == 2) return false;        // TEST-NET-1
        if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;
        if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;     // TEST-NET-2
        if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;      // TEST-NET-3
        return true;
    }
}

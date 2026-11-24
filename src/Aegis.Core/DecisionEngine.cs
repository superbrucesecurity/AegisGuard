namespace Aegis.Core;

/// <summary>
/// Reglas de decisión deterministas. La IA nunca puede, por sí sola, bloquear o
/// poner en cuarentena: como máximo puede elevar la monitorización o reforzar
/// una evidencia local ya suficiente.
/// </summary>
public sealed class DecisionEngine
{
    public DecisionResult Decide(Observation observation, LocalAssessment local, AiClassification ai, PolicySettings policy)
    {
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(ai);
        ArgumentNullException.ThrowIfNull(policy);

        policy.Validate();

        var aiSignal = ai.IsValid ? NormalizeAiSignal(ai) : 0;
        // Si la IA no responde o está desactivada, la evidencia local conserva todo su peso.
        var risk = ai.IsValid
            ? Math.Clamp(local.Score * (1 - policy.AiWeight) + aiSignal * 100 * policy.AiWeight, 0, 100)
            : Math.Clamp(local.Score, 0, 100);

        var reasons = new List<string>();
        foreach (var c in local.Contributions.OrderByDescending(x => x.Weight).Take(4))
        {
            reasons.Add($"{c.Source}: {c.Reason} (+{c.Weight:0})");
        }

        if (ai.IsValid)
        {
            reasons.Add($"IA {ai.Model}: {ai.ChoiceLabel} p={ai.Malicious:0.00} conf={ai.Confidence:0.00}");
        }
        else if (policy.AiEnabled)
        {
            reasons.Add("IA no disponible: se decide solo con evidencia local");
        }

        var evidenceConfidence = Math.Clamp(0.55 + local.EvidenceCount * 0.09, 0.55, 0.96);
        var confidence = ai.IsValid
            ? Math.Clamp(evidenceConfidence * 0.65 + ai.Confidence * 0.35, 0, 0.99)
            : evidenceConfidence;

        var verdict = Verdict.Allow;
        if (risk >= policy.QuarantineThreshold && policy.AutoQuarantine)
        {
            verdict = Verdict.Quarantine;
        }
        else if (risk >= policy.BlockThreshold)
        {
            verdict = Verdict.Block;
        }
        else if (risk >= policy.MonitorThreshold)
        {
            verdict = Verdict.Monitor;
        }

        if (local.HasCriticalIndicator && observation.Kind is EventKind.FileCreated or EventKind.FileModified or EventKind.ManualScan)
        {
            if (policy.AutoQuarantine)
            {
                verdict = Verdict.Quarantine;
            }
            else if (verdict == Verdict.Allow)
            {
                verdict = Verdict.Block;
            }
        }

        if (!ai.IsValid && verdict == Verdict.Quarantine && !local.HasCriticalIndicator && local.Score < policy.QuarantineThreshold)
        {
            verdict = Verdict.Block;
        }

        // Un único indicador de IA, sin respaldo local, nunca destruye ni bloquea.
        var aiWasDecisive = false;
        if (ai.IsValid && ai.Malicious >= 0.85 && ai.Confidence >= 0.8 && local.Score < 30)
        {
            if (verdict == Verdict.Allow)
            {
                verdict = Verdict.Monitor;
            }
            aiWasDecisive = verdict == Verdict.Monitor;
            reasons.Add("IA sospechosa sin respaldo local: elevada a monitorización");
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
            Ai = ai,
            Reasons = reasons,
            AiWasDecisive = aiWasDecisive
        };
    }

    public LocalAssessment Assess(Observation observation, IReadOnlyList<RuleMatch> ruleMatches, IReadOnlySet<string> maliciousHashes)
    {
        var assessment = new LocalAssessment();
        void Add(string source, string reason, double weight, bool critical = false)
        {
            assessment.Score += weight;
            assessment.EvidenceCount++;
            assessment.Contributions.Add(new ScoreContribution { Source = source, Reason = reason, Weight = weight });
            if (critical)
            {
                assessment.HasCriticalIndicator = true;
            }
        }

        if (!string.IsNullOrWhiteSpace(observation.Sha256) && maliciousHashes.Contains(observation.Sha256, StringComparer.OrdinalIgnoreCase))
        {
            Add("hash", "Hash en lista de denegación", 100, true);
        }

        foreach (var rule in ruleMatches)
        {
            var weight = rule.Severity switch
            {
                Severity.Critical => 65,
                Severity.High => 42,
                Severity.Medium => 22,
                Severity.Low => 9,
                _ => 2
            };
            Add("yara", $"{rule.RuleId}: {rule.Name}", weight, rule.Severity == Severity.Critical);
        }

        if (observation.Signature == SignatureStatus.SignedUntrusted)
        {
            Add("signature", "Firma digital no válida", 34);
        }
        else if (observation.Signature == SignatureStatus.Unsigned && IsExecutable(observation))
        {
            Add("signature", "Ejecutable sin firma digital", 12);
        }

        if (observation.Reputation < 0.2)
        {
            Add("reputation", "Reputación muy baja", 28);
        }
        else if (observation.Reputation < 0.45)
        {
            Add("reputation", "Reputación baja", 12);
        }

        foreach (var flag in observation.BehaviorFlags.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var weight = flag switch
            {
                "ransomware_canary_modified" or "credential_store_access" or "lsass_handle_requested" => 55,
                "process_injection" or "privilege_escalation" or "av_tampering" => 50,
                "persistence_registry" or "persistence_service" or "persistence_task" => 35,
                "mass_file_rename" or "mass_file_encrypt" => 48,
                "c2_beacon" or "dns_tunneling" => 45,
                "unsigned_service" or "hidden_process" => 25,
                "unusual_parent" or "temp_execution" => 14,
                _ => 8
            };
            Add("behavior", flag, weight, weight >= 50);
        }

        if (!string.IsNullOrWhiteSpace(observation.RemoteAddress) && IsPublicIp(observation.RemoteAddress))
        {
            Add("network", "Conexión a IP pública", 6);
        }

        assessment.Score = Math.Clamp(assessment.Score, 0, 100);
        return assessment;
    }

    private static double NormalizeAiSignal(AiClassification ai)
    {
        var weighted = ai.Clean * 0 + ai.Suspicious * 0.55 + ai.Malicious * 1.0;
        var baseSignal = Math.Clamp(weighted, 0, 1);
        var confidenceFactor = Math.Clamp(ai.Confidence, 0.2, 1);
        return Math.Clamp(baseSignal * confidenceFactor + ai.SeverityScore / 3 * 0.1 * confidenceFactor, 0, 1);
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
        return ext is "exe" or "dll" or "sys" or "scr" or "com" or "msi" or "ps1" or "bat" or "cmd" or "vbs" or "js" or "hta";
    }

    private static bool IsPublicIp(string value)
    {
        if (!System.Net.IPAddress.TryParse(value, out var ip)) return false;
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return !ip.IsIPv6LinkLocal && !ip.IsIPv6SiteLocal && !ip.IsIPv6Multicast;
        }
        var b = ip.GetAddressBytes();
        return !(b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || b[0] == 127 || (b[0] == 169 && b[1] == 254));
    }
}

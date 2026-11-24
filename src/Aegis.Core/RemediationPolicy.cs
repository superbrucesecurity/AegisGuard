namespace Aegis.Core;

/// <summary>
/// Decide cuándo se aplica una acción automática. El modo aprendizaje observa
/// y registra las decisiones sin tocar el sistema, salvo ante indicios
/// verificados en el propio equipo (hash en lista local o regla EICAR), que
/// siguen aplicándose para no desarmar la protección básica.
/// </summary>
public static class RemediationPolicy
{
    public static bool ShouldQuarantine(DecisionResult decision, PolicySettings policy) =>
        decision.Verdict == Verdict.Quarantine &&
        policy.AutoQuarantine &&
        (!policy.LearningMode || decision.Local.HasVerifiedIndicator);

    public static bool ShouldBlockNetwork(DecisionResult decision, PolicySettings policy) =>
        (decision.Verdict is Verdict.Block or Verdict.Quarantine) &&
        policy.AutoBlockNetwork &&
        (!policy.LearningMode || decision.Local.HasVerifiedIndicator);
}

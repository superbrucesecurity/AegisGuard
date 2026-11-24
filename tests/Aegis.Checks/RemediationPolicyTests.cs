using Aegis.Core;

namespace Aegis.Tests;

public sealed class RemediationPolicyTests
{
    private static DecisionResult Decision(Verdict verdict, bool verified = false) => new()
    {
        Verdict = verdict,
        Local = new LocalAssessment { HasVerifiedIndicator = verified }
    };

    private static PolicySettings Policy(bool learning, bool autoQuarantine = true, bool autoBlock = true) => new()
    {
        LearningMode = learning,
        AutoQuarantine = autoQuarantine,
        AutoBlockNetwork = autoBlock
    };

    [Fact]
    public void LearningModeSuppressesQuarantineAndNetworkBlock()
    {
        var decision = Decision(Verdict.Quarantine);
        var policy = Policy(learning: true);

        Assert.False(RemediationPolicy.ShouldQuarantine(decision, policy));
        Assert.False(RemediationPolicy.ShouldBlockNetwork(decision, policy));
    }

    [Fact]
    public void VerifiedIndicatorStillQuarantinesInLearningMode()
    {
        var decision = Decision(Verdict.Quarantine, verified: true);
        var policy = Policy(learning: true);

        Assert.True(RemediationPolicy.ShouldQuarantine(decision, policy));
        Assert.True(RemediationPolicy.ShouldBlockNetwork(decision, policy));
    }

    [Fact]
    public void PolicySwitchesAreHonoredOutsideLearningMode()
    {
        var decision = Decision(Verdict.Block);

        Assert.True(RemediationPolicy.ShouldBlockNetwork(decision, Policy(learning: false)));
        Assert.False(RemediationPolicy.ShouldBlockNetwork(decision, Policy(learning: false, autoBlock: false)));
        Assert.False(RemediationPolicy.ShouldQuarantine(Decision(Verdict.Quarantine), Policy(learning: false, autoQuarantine: false)));
    }
}

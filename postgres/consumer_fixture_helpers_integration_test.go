//go:build integration

package postgres_test

import (
	"time"

	"github.com/faustbrian/go-identity/risk"
	organization "github.com/faustbrian/go-organization"
)

// These unchanged private fixture helpers are retained on each side of the
// test-module boundary; they add no production API, store or authority.
func baselineRiskPolicy(version uint64, screening, reset bool, change ...bool) (risk.Policy, error) {
	return risk.NewPolicy(baselineRiskPolicyConfig(version, screening, reset, change...))
}

func baselineRiskPolicyConfig(version uint64, screening, reset bool, change ...bool) risk.PolicyConfig {
	c := risk.PolicyConfig{Version: version, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}}
	if screening {
		c.HIBP = risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.signup"}}
		if reset {
			c.HIBP.Operations = append(c.HIBP.Operations, "identity.password.reset-complete")
		}
		if len(change) == 1 && change[0] {
			c.HIBP.Operations = append(c.HIBP.Operations, "identity.password.change")
		}
	}
	return c
}

func customRoleConfig() organization.DynamicRoleConfig {
	return organization.DynamicRoleConfig{Version: 1, MaximumRoles: 2, Catalog: []organization.Permission{{ID: "document-read", Action: "document.read", ResourceType: "document"}, {ID: "document-write", Action: "document.write", ResourceType: "document"}}}
}

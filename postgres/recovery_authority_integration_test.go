//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Recovery has three external decision sites: the general organization read,
// current management action, and kernel outcome-disclosure policy. A permitted
// decision cannot turn pre-callback native admission into a lease.
type recoveryWithdrawalPolicy struct {
	fixture           *orgFixture
	operation         organization.Operation
	stage, withdrawal string
	tenant, user      string
	armed, fired      bool
}

func (p *recoveryWithdrawalPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	match := p.stage == "get" && c.Request.Action == authorization.Action(organization.Get) && c.Request.Resource.Type == "organization" || p.stage == "management" && c.Request.Action == authorization.Action(p.operation) && c.Request.Resource.Type == "organization" || p.stage == "query" && c.Request.Action == authorization.Action(p.operation) && c.Request.Resource.Type == "identity.user"
	if p.armed && match {
		p.armed = false
		p.fired = true
		tenant, user := "org-test-basic", "second"
		if p.tenant != "" {
			tenant, user = p.tenant, p.user
		}
		var err error
		switch p.withdrawal {
		case "session":
			_, err = p.fixture.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, tenant, user)
		case "member":
			_, err = p.fixture.pool.Raw().Exec(ctx, `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, tenant, user)
		case "role":
			_, err = p.fixture.pool.Raw().Exec(ctx, `UPDATE organization.memberships SET role='member',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, tenant, user)
		case "epoch":
			_, err = p.fixture.pool.Raw().Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1`, tenant)
		case "scoped-authority":
			scope, e := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, identity.UserID(user))
			if e != nil {
				return authorization.Decision{}, e
			}
			_, err = authority.AdvanceAuthority(ctx, p.fixture.pool.Raw(), scope, 1, time.Second)
		}
		if err != nil {
			return authorization.Decision{}, err
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}

func TestRecoveryRevalidatesAuthorityAfterEveryPolicyCallback(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateTeam, organization.Update} {
		for _, stage := range []string{"get", "management", "query"} {
			for _, withdrawal := range []string{"session", "member", "role", "epoch", "scoped-authority"} {
				t.Run(string(op)+"/"+stage+"/"+withdrawal, func(t *testing.T) {
					f := teamFixture(t)
					tenant := "org-test-basic"
					f.create(t, tenant)
					f.add(t, tenant, "second", organization.RoleAdministrator, 1)
					var p organizationpg.PreparedCommand
					var err error
					if op == organization.Update {
						p, err = f.service.PrepareUpdate(f.ctx, metadataRequest(t, f, tenant, "second", 2), "127.0.0.1")
					} else {
						p, err = f.service.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth(tenant, "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 2, TeamID: "engineering", Name: "Engineering", CorrelationID: "recovery-admission"}, "127.0.0.1")
					}
					if err != nil {
						t.Fatal(err)
					}
					committedTeam(t, f, p)
					handle, err := p.Recovery()
					if err != nil {
						t.Fatal(err)
					}
					policy := &recoveryWithdrawalPolicy{fixture: f, operation: op, stage: stage, withdrawal: withdrawal}
					config := f.configuration
					config.Authorization = policy
					config.Coordinator, err = kernel.NewCoordinator(f.pool, config.Registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}})
					if err != nil {
						t.Fatal(err)
					}
					service, err := organizationpg.NewService(f.participant, config)
					if err != nil {
						t.Fatal(err)
					}
					// Unchanged authority must disclose the exact original historical result.
					got, err := service.Recover(f.ctx, f.auth(tenant, "second"), handle)
					if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
						t.Fatal("legitimate current recovery denied", err)
					}
					policy.armed = true
					got, err = service.Recover(f.ctx, f.auth(tenant, "second"), handle)
					if !policy.fired {
						t.Fatal("required callback stage was not exercised")
					}
					if !errors.Is(err, organization.ErrForbidden) || got != (organization.StoreResult{}) {
						t.Fatal("withdrawn recovery authority disclosed retained outcome", err, got.Receipt.Outcome)
					}
				})
			}
		}
	}
}

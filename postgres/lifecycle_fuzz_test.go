package postgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	organization "github.com/faustbrian/go-organization"
)

// This is bounded structural decoder evidence only. Opaque primary sources are
// never invoked here; the genuine native journey separately proves their signed
// provenance, current session/factor admission and transactional consumption.
func FuzzLifecycleNativeFrameBoundary(f *testing.F) {
	for _, reason := range []string{"maintenance", "", "bad reason", "\x00"} {
		f.Add(reason, "active", uint64(1), true)
	}
	f.Fuzz(func(t *testing.T, reason, state string, version uint64, owner bool) {
		if len(reason) > 256 || len(state) > 128 {
			return
		}
		p := Contributor{config: ContributorConfig{Lifecycle: organization.LifecycleConfig{Version: 1, ProofAudience: "lifecycle"}, ArchivePrimary: new(passwordpg.ActionPrimarySource)}}
		role := organization.RoleOwner
		if !owner {
			role = organization.RoleAdministrator
		}
		c := nativeCommand{operation: organization.Archive, spec: identity.FeatureCommandSpec{Binding: identity.CommandBinding{ActorKind: authorization.SubjectUser, ActorID: "owner", UserID: "owner"}}, org: organization.Organization{Version: 1}, actor: organization.Member{Role: role, Version: 1, AuthorizationVersion: 1}, actorFactorVersion: 1, targetFactorVersion: 1}
		text := func(name string) string {
			if name == "lifecycle-state" {
				return state
			}
			if name == "lifecycle-reason" {
				return reason
			}
			return ""
		}
		number := func(name string) uint64 {
			if name == "lifecycle-policy-version" {
				return version
			}
			return 0
		}
		e := p.decodeLifecycle(&c, text, number)
		valid := owner && state == "active" && version == 1 && len(reason) > 0 && len(reason) <= 64
		for _, b := range []byte(reason) {
			if b < 33 || b > 126 {
				valid = false
			}
		}
		if valid && e != nil {
			t.Fatal("valid lifecycle frame rejected", e)
		}
		if !valid && e == nil {
			t.Fatal("malformed lifecycle frame accepted")
		}
	})
}

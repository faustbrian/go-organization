package organization

import (
	"strings"
	"testing"
)

// Recipient listing reuses this existing bounded decoder, not a second cursor
// authority. Scope/authentication behavior is covered through public ListMine.
func FuzzInvitationListMineCursor(f *testing.F) {
	var scope [32]byte
	scope[0] = 19
	for _, value := range []string{"", string(encodeOrganizationCursor(scope, "invitation-a")), "=", "a\x00b", strings.Repeat("x", 513), string(encodeOrganizationCursor(scope, ID(strings.Repeat("é", 64))))} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		after, binding, err := parseOrganizationCursor(OrganizationCursor(value))
		if err != nil || value == "" {
			return
		}
		if len(value) > 512 || !safeID(string(after)) || string(encodeOrganizationCursor(binding, after)) != value {
			t.Fatal("recipient cursor escaped canonical bounds")
		}
	})
}

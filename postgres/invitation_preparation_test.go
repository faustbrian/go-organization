package postgres

import (
	"context"
	"crypto/sha256"
	"testing"

	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Restore accepts only an authenticated, exact original checkpoint. Exercise
// both hostile ciphertext and malformed authenticated plaintext without SQL or
// generated capability custody; neither can produce an execution authority.
func FuzzInvitationPreparationRejectsMalformedCheckpoint(f *testing.F) {
	for _, seed := range [][]byte{nil, []byte("{}"), []byte(`{"Schema":1}`), []byte(`{"Schema":1,"unknown":true}`), []byte(`{} {}`)} {
		f.Add(seed)
	}
	key := sha256.Sum256([]byte("organization-invitation-checkpoint-fuzz-key"))
	provider, err := keyring.New(map[string][]byte{"test": key[:]})
	if err != nil {
		f.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		p := &invitationPhase{service: &InvitationService{crypto: crypto}}
		if err := p.restore(context.Background(), 1, data); err == nil || p.execution != nil {
			t.Fatal("untrusted checkpoint became execution authority")
		}
		aad, err := p.outputContext(1)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: data, KeyReference: "test", Context: aad})
		if err != nil {
			// Empty plaintext is rejected by the envelope owner, before restore.
			if len(data) == 0 {
				return
			}
			t.Fatal(err)
		}
		wire, err := sealed.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := p.restore(context.Background(), 1, wire); err == nil || p.execution != nil {
			t.Fatal("malformed authenticated checkpoint became execution authority")
		}
	})
}

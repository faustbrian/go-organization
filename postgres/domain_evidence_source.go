package postgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// DomainEvidenceSource selects the trusted external observer and authenticates
// its organization-issued observation across the public contributor boundary.
// Keep the key secret and stable while prepared commands may execute. Recovery
// needs neither the key nor another observation; it reads retained primary proof.
type DomainEvidenceSource struct {
	observer organization.DomainEvidenceObserver
	key      [32]byte
}

// NewDomainEvidenceSource selects a trusted observer and secret admission key.
// Zero/nil inputs are invalid; callers supply cryptographically random key bytes.
func NewDomainEvidenceSource(observer organization.DomainEvidenceObserver, key [32]byte) (*DomainEvidenceSource, error) {
	if observer == nil || key == ([32]byte{}) {
		return nil, organization.ErrInvalidInput
	}
	return &DomainEvidenceSource{observer: observer, key: key}, nil
}
func (DomainEvidenceSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.DomainEvidenceSource(redacted)"))
}
func (DomainEvidenceSource) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (DomainEvidenceSource) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

func (s *DomainEvidenceSource) seal(b identity.CommandBinding, p organization.DomainProof) string {
	if s == nil {
		return ""
	}
	payload, _ := json.Marshal(struct {
		Binding identity.CommandBinding
		Proof   organization.DomainProof
	}{b, p})
	h := hmac.New(sha256.New, s.key[:])
	_, _ = h.Write([]byte("organization.domain-evidence.v1\x00"))
	_, _ = h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *DomainEvidenceSource) valid(b identity.CommandBinding, p organization.DomainProof, signature string) bool {
	if s == nil {
		return false
	}
	expected, err := hex.DecodeString(s.seal(b, p))
	if err != nil {
		return false
	}
	actual, err := hex.DecodeString(signature)
	return err == nil && hmac.Equal(actual, expected)
}

func isEvidenceMutation(op organization.Operation) bool {
	return op == organization.ApplyDomainProof || op == organization.RevokeDomainProof
}

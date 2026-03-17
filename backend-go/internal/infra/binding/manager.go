package binding

import (
	"context"
	"fmt"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/service"
)

type Config struct {
	ProfileID      string
	ProofAlgorithm string
	KeyID          string
	Secret         []byte
}

type Manager struct {
	cfg Config
}

func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

func (m *Manager) Create(_ context.Context, payload any, label service.Label) (service.BindingRecord, error) {
	payloadHash, err := PayloadHash(payload)
	if err != nil {
		return service.BindingRecord{}, fmt.Errorf("compute payload hash: %w", err)
	}
	labelHash, err := LabelHash(label)
	if err != nil {
		return service.BindingRecord{}, fmt.Errorf("compute label hash: %w", err)
	}
	proof, err := m.proof(payloadHash, labelHash)
	if err != nil {
		return service.BindingRecord{}, err
	}

	now := time.Now().UTC()
	return service.BindingRecord{
		ProfileID:      m.cfg.ProfileID,
		KeyID:          m.cfg.KeyID,
		PayloadHash:    payloadHash,
		LabelHash:      labelHash,
		Proof:          proof,
		ProofAlgorithm: m.cfg.ProofAlgorithm,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

func (m *Manager) Verify(_ context.Context, payload any, label service.Label, binding service.BindingRecord) error {
	if binding.ProfileID != m.cfg.ProfileID {
		return fmt.Errorf("%w: profile_id mismatch", service.ErrBindingCorrupted)
	}
	if binding.ProofAlgorithm != m.cfg.ProofAlgorithm {
		return fmt.Errorf("%w: proof_algorithm mismatch", service.ErrBindingCorrupted)
	}
	if binding.KeyID != m.cfg.KeyID {
		return fmt.Errorf("%w: key_id mismatch", service.ErrBindingCorrupted)
	}

	payloadHash, err := PayloadHash(payload)
	if err != nil {
		return fmt.Errorf("%w: recompute payload hash: %v", service.ErrBindingCorrupted, err)
	}
	if payloadHash != binding.PayloadHash {
		return fmt.Errorf("%w: payload hash mismatch", service.ErrBindingInvalid)
	}

	labelHash, err := LabelHash(label)
	if err != nil {
		return fmt.Errorf("%w: recompute label hash: %v", service.ErrBindingCorrupted, err)
	}
	if labelHash != binding.LabelHash {
		return fmt.Errorf("%w: label hash mismatch", service.ErrBindingInvalid)
	}

	if ok := VerifyHMACProof(m.cfg.Secret, payloadHash, labelHash, binding.Proof); !ok {
		return fmt.Errorf("%w: proof mismatch", service.ErrBindingInvalid)
	}

	return nil
}

func (m *Manager) proof(payloadHash string, labelHash string) (string, error) {
	if len(m.cfg.Secret) == 0 {
		return "", fmt.Errorf("%w: empty binding secret", service.ErrBindingCorrupted)
	}
	if m.cfg.ProofAlgorithm != "hmac-sha256" {
		return "", fmt.Errorf("%w: unsupported proof algorithm %s", service.ErrBindingCorrupted, m.cfg.ProofAlgorithm)
	}
	return HMACProof(m.cfg.Secret, payloadHash, labelHash), nil
}

var _ service.BindingIssuer = (*Manager)(nil)
var _ service.BindingVerifier = (*Manager)(nil)

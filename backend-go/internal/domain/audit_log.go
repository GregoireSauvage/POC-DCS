package domain

import "time"

// AuditLog represents an audit log entry for DCS decisions
type AuditLog struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	// Request context
	RequestID string `json:"request_id"`
	TenantID  string `json:"tenant_id"`

	// Subject (who)
	SubjectUserID string `json:"subject_user_id"`
	SubjectRole   string `json:"subject_role"`

	// Action (what)
	Action string `json:"action"`

	// Resource (on what)
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id,omitempty"`

	// Decision outcome
	Outcome      string `json:"outcome"` // allow, deny, error
	DecisionHash string `json:"decision_hash"`

	// Field-level access tracking
	FieldsDecrypted []string `json:"fields_decrypted"`
	FieldsMasked    []string `json:"fields_masked"`
	FieldsDenied    []string `json:"fields_denied"`

	// Additional details (JSON)
	Details map[string]interface{} `json:"details,omitempty"`
}

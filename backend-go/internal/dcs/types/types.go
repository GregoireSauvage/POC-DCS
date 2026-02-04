package types

type Classification string

const (
	ClassificationPublic    Classification = "PUBLIC"
	ClassificationInternal  Classification = "INTERNAL"
	ClassificationSensitive Classification = "SENSITIVE"
	ClassificationPII       Classification = "PII"
)

type FieldAction string

const (
	FieldActionAllow            FieldAction = "allow"
	FieldActionDecrypt          FieldAction = "decrypt"
	FieldActionMaskAfterDecrypt FieldAction = "mask_after_decrypt"
	FieldActionDeny             FieldAction = "deny"
)

type Principal struct {
	TenantID string
	UserID   string
	Username string
	Role     string
	Scopes   []string
}

type RequestContext struct {
	RequestID   string
	ClientIP    string
	Channel     string
	Purpose     string
	DeviceTrust float64
	Env         string
}

type FieldMeta struct {
	Classification Classification
	Crypto         map[string]string
}

type Resource struct {
	Type     string
	ID       string
	OwnerID  string
	TenantID string
	Labels   []string
	Fields   map[string]FieldMeta
}

type PolicyInput struct {
	Principal Principal
	Action    string
	Resource  Resource
	Context   RequestContext
}

type Decision struct {
	Allow        bool
	FieldActions map[string]FieldAction
	Reason       string
}

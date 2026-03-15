package service

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
	Access   AccessContext
	Resource Resource
}

type Decision struct {
	Allow        bool
	FieldActions map[string]FieldAction
	Reason       string
	Hash         string
}

package service

type ClassificationPolicy interface {
	PolicyID() string
	PolicyVersion() string
	DefaultClassification() Classification
	IsReadAction(action Action) bool
	IsWriteAction(action Action) bool
	IsBootstrapAction(action Action) bool
	IsAuditAction(action Action) bool
	FieldActionFor(role string, cls Classification) FieldAction
	HardenedFields(resourceType string, role string) []string
}

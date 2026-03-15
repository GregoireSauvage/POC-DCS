package service

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

type Obligation struct {
	Field  string
	Action FieldAction
}

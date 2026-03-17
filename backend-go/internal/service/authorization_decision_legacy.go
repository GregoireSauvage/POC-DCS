package service

// AuthorizationDecision is retained only as a legacy DTO for internal/dcs/*.
// The runtime nominal no longer depends on the old enforcer interface.
type AuthorizationDecision struct {
	Allow         bool
	Reason        string
	DecisionHash  string
	PolicyID      string
	PolicyVersion string
}

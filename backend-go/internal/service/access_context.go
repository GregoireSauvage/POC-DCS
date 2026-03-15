package service

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

type AccessContext struct {
	Principal Principal
	Request   RequestContext
	Action    Action
}

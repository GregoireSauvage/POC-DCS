package domain

import "time"

type Film struct {
	TenantID      string
	ID            string
	Title         string
	TimeElapsedCT string
	Labels        []string
	CreatedAt     time.Time
}

type Hall struct {
	TenantID      string
	ID            string
	Name          string
	OwnerUserID   string
	CurrentFilmID string
	Labels        []string
	CreatedAt     time.Time
}

type Spectator struct {
	TenantID         string
	ID               string
	HallID           string
	NameCT           string
	AgeCT            string
	ExternalIDCT     string
	ExternalIDLookup []byte
	Labels           []string
	CreatedAt        time.Time
}

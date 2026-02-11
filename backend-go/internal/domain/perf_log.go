package domain

import "time"

// PerfLog represents a performance log entry
type PerfLog struct {
	Timestamp time.Time `json:"ts"`

	RequestID string `json:"request_id"`
	TenantID  string `json:"tenant_id"`

	SubjectUserID string `json:"subject_user_id"`
	SubjectRole   string `json:"subject_role"`

	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`

	DCSEnabled bool `json:"dcs_enabled"`
	CacheLevel int  `json:"cache_level"`

	TotalMS float64  `json:"total_ms"`
	PIPMS   *float64 `json:"pip_ms"`
	PDPMS   *float64 `json:"pdp_ms"`
	KMSMS   *float64 `json:"kms_ms"`
	DBMS    *float64 `json:"db_ms"`
}

// PerfSummary represents aggregated performance data
type PerfSummary struct {
	Action     string   `json:"action"`
	DCSEnabled bool     `json:"dcs_enabled"`
	CacheLevel int      `json:"cache_level"`
	AvgTotalMS *float64 `json:"avg_total_ms"`
	Count      int      `json:"count"`
}

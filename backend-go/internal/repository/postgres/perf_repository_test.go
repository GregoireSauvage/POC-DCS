package postgres

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgtype"
)

type fakeRow struct {
	values []interface{}
	err    error
}

func (r fakeRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return fmt.Errorf("dest count %d != values count %d", len(dest), len(r.values))
	}
	for i := range dest {
		if err := assignValue(dest[i], r.values[i]); err != nil {
			return err
		}
	}
	return nil
}

func assignValue(dest interface{}, val interface{}) error {
	switch d := dest.(type) {
	case *time.Time:
		if val == nil {
			return errors.New("nil time value")
		}
		*d = val.(time.Time)
	case *string:
		if val == nil {
			*d = ""
			return nil
		}
		*d = val.(string)
	case *bool:
		if val == nil {
			*d = false
			return nil
		}
		*d = val.(bool)
	case *int:
		if val == nil {
			*d = 0
			return nil
		}
		*d = val.(int)
	case *float64:
		if val == nil {
			*d = 0
			return nil
		}
		*d = val.(float64)
	case **float64:
		if val == nil {
			*d = nil
			return nil
		}
		v := val.(float64)
		*d = &v
	case **string:
		if val == nil {
			*d = nil
			return nil
		}
		v := val.(string)
		*d = &v
	case *pgtype.UUID:
		if val == nil {
			d.Status = pgtype.Null
			return nil
		}
		switch v := val.(type) {
		case pgtype.UUID:
			*d = v
		case *pgtype.UUID:
			if v == nil {
				d.Status = pgtype.Null
				return nil
			}
			*d = *v
		case uuid.UUID:
			d.Bytes = v
			d.Status = pgtype.Present
		case string:
			parsed, err := uuid.Parse(v)
			if err != nil {
				return err
			}
			d.Bytes = parsed
			d.Status = pgtype.Present
		default:
			return fmt.Errorf("unsupported pgtype.UUID value %T", val)
		}
	default:
		return fmt.Errorf("unsupported dest type %T", dest)
	}
	return nil
}

func TestScanPerfLog_AllFields(t *testing.T) {
	ts := time.Now().UTC()
	pip := 1.1
	pdp := 2.2
	kms := 3.3
	db := 4.4
	subjectID := uuid.New()

	row := fakeRow{
		values: []interface{}{
			ts,
			"req-1",
			"t1",
			subjectID,
			"admin",
			"film.read",
			"film",
			true,
			2,
			12.34,
			pip,
			pdp,
			kms,
			db,
		},
	}

	log, err := scanPerfLog(row)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if log.RequestID != "req-1" || log.Action != "film.read" {
		t.Fatalf("unexpected log fields")
	}
	if log.PIPMS == nil || *log.PIPMS != pip {
		t.Fatalf("expected pip_ms %v, got %v", pip, log.PIPMS)
	}
	if log.PDPMS == nil || *log.PDPMS != pdp {
		t.Fatalf("expected pdp_ms %v, got %v", pdp, log.PDPMS)
	}
	if log.KMSMS == nil || *log.KMSMS != kms {
		t.Fatalf("expected kms_ms %v, got %v", kms, log.KMSMS)
	}
	if log.DBMS == nil || *log.DBMS != db {
		t.Fatalf("expected db_ms %v, got %v", db, log.DBMS)
	}
}

func TestScanPerfLog_NullOptionalFields(t *testing.T) {
	ts := time.Now().UTC()
	subjectID := uuid.New()

	row := fakeRow{
		values: []interface{}{
			ts,
			"req-2",
			"t1",
			subjectID,
			"admin",
			"film.update",
			"film",
			false,
			0,
			5.6,
			nil,
			nil,
			nil,
			nil,
		},
	}

	log, err := scanPerfLog(row)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if log.PIPMS != nil || log.PDPMS != nil || log.KMSMS != nil || log.DBMS != nil {
		t.Fatalf("expected optional perf fields to be nil")
	}
}

func TestScanPerfSummary_AllFields(t *testing.T) {
	avg := 12.34
	row := fakeRow{
		values: []interface{}{
			"film.read",
			true,
			1,
			avg,
			10,
		},
	}

	summary, err := scanPerfSummary(row)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if summary.Action != "film.read" || summary.Count != 10 {
		t.Fatalf("unexpected summary fields")
	}
	if summary.AvgTotalMS == nil || *summary.AvgTotalMS != avg {
		t.Fatalf("expected avg_total_ms %v, got %v", avg, summary.AvgTotalMS)
	}
}

func TestScanPerfSummary_NullAvg(t *testing.T) {
	row := fakeRow{
		values: []interface{}{
			"film.read",
			true,
			1,
			nil,
			0,
		},
	}

	summary, err := scanPerfSummary(row)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if summary.AvgTotalMS != nil {
		t.Fatalf("expected avg_total_ms nil")
	}
}

func TestScanPerfLog_PropagatesScanError(t *testing.T) {
	scanErr := errors.New("scan error")
	row := fakeRow{err: scanErr, values: make([]interface{}, 14)}
	_, err := scanPerfLog(row)
	if !errors.Is(err, scanErr) {
		t.Fatalf("expected scan error, got %v", err)
	}
}

func TestScanPerfSummary_PropagatesScanError(t *testing.T) {
	scanErr := errors.New("scan error")
	row := fakeRow{err: scanErr, values: make([]interface{}, 5)}
	_, err := scanPerfSummary(row)
	if !errors.Is(err, scanErr) {
		t.Fatalf("expected scan error, got %v", err)
	}
}

var _ pgx.Row = fakeRow{}

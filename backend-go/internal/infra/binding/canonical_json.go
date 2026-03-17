package binding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
)

func CanonicalJSON(value any) ([]byte, error) {
	normalized, err := normalizeCanonicalValue(reflect.ValueOf(value))
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(normalized); err != nil {
		return nil, err
	}

	return bytes.TrimSpace(buffer.Bytes()), nil
}

func normalizeCanonicalValue(value reflect.Value) (any, error) {
	if !value.IsValid() {
		return nil, nil
	}

	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil, nil
		}
		value = value.Elem()
	}

	if value.Type() == reflect.TypeOf(time.Time{}) {
		timestamp := value.Interface().(time.Time)
		return timestamp.UTC().Format(time.RFC3339Nano), nil
	}

	switch value.Kind() {
	case reflect.Struct:
		result := make(map[string]any)
		valueType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := valueType.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := field.Name
			if tag, ok := field.Tag.Lookup("json"); ok {
				if tag == "-" {
					continue
				}
				parts := strings.Split(tag, ",")
				if parts[0] != "" {
					name = parts[0]
				}
			}
			normalized, err := normalizeCanonicalValue(value.Field(i))
			if err != nil {
				return nil, err
			}
			result[name] = normalized
		}
		return result, nil
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("canonical json requires string map keys, got %s", value.Type().Key())
		}
		result := make(map[string]any, value.Len())
		iter := value.MapRange()
		for iter.Next() {
			normalized, err := normalizeCanonicalValue(iter.Value())
			if err != nil {
				return nil, err
			}
			result[iter.Key().String()] = normalized
		}
		return result, nil
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return []any{}, nil
		}
		result := make([]any, 0, value.Len())
		for i := 0; i < value.Len(); i++ {
			normalized, err := normalizeCanonicalValue(value.Index(i))
			if err != nil {
				return nil, err
			}
			result = append(result, normalized)
		}
		return result, nil
	case reflect.String:
		return value.String(), nil
	case reflect.Bool:
		return value.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint(), nil
	case reflect.Float32, reflect.Float64:
		return value.Float(), nil
	default:
		return value.Interface(), nil
	}
}

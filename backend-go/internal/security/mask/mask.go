package mask

import (
	"strconv"
	"strings"
)

func String(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 2 {
		return strings.Repeat("*", len(value))
	}
	return value[:1] + "***"
}

func Age(value int) string {
	if value < 18 {
		return "-18"
	}
	return "+18"
}

func UUID(value string) string {
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "…"
}

func Field(field string, plaintext string) string {
	switch {
	case field == "age":
		age, err := strconv.Atoi(plaintext)
		if err != nil {
			return "***"
		}
		return Age(age)
	case strings.HasSuffix(field, "_id") && field != "external_id":
		return UUID(plaintext)
	default:
		return String(plaintext)
	}
}

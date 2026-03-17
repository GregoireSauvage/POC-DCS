package binding

import "encoding/json"

func CanonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

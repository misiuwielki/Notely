package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		input  http.Header
		result string
		err    error
	}{
		{
			input:  http.Header{"Authorization": []string{"ApiKey 1554586435415456486456456"}},
			result: "1554586435415456486456456",
			err:    nil,
		},
		{
			input:  http.Header{},
			result: "",
			err:    ErrNoAuthHeaderIncluded,
		},
		{
			input:  http.Header{"Authorization": []string{"ApiKey1554586435415456486456456"}},
			result: "",
			err:    errors.New("malformed authorization header"),
		},
		{
			input:  http.Header{"Authorization": []string{"ApiKey1554586435415456486456456 1554586435415456486456456"}},
			result: "",
			err:    errors.New("malformed authorization header"),
		},
		{
			input:  http.Header{"Authorization": []string{"ApiKe 1554586435415456486456456"}},
			result: "",
			err:    errors.New("malformed authorization header"),
		},
		{
			input:  http.Header{"Authorization": []string{"ApiKey 1554586435415456486456456 lulz"}},
			result: "1554586435415456486456456",
			err:    nil,
		},
		{
			input:  http.Header{"Auth": []string{"ApiKey 1554586435415456486456456"}},
			result: "",
			err:    ErrNoAuthHeaderIncluded,
		},
	}
	for i, c := range cases {
		key, err := GetAPIKey(c.input)
		if key != c.result {
			t.Fatalf("got incorrect key: %s, expected %s, case %d", key, c.result, i+1)
		}
		if (err != nil) != (c.err != nil) {
			t.Errorf("expected error presence: %v, got: %v, case %d", err, c.err, i+1)
		}
		if err != nil && err.Error() != c.err.Error() {
			t.Fatalf("invalid error: %v, expected error: %v, case %d", err, c.err, i+1)
		}
	}
}

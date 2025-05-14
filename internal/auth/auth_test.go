package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		headers http.Header
		name    string
		xpc     string
		err     error
	}{
		{
			name:    "Success with Authorization header",
			headers: http.Header{"Authorization": []string{"ApiKey key123"}},
			xpc:     "key123",
			err:     nil,
		},
		{
			name:    "Error no Authorization header",
			headers: http.Header{},
			xpc:     "",
			err:     ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed authorization header single arg",
			headers: http.Header{"Authorization": []string{"ApiKeykey123"}},
			xpc:     "",
			err:     ErrMalformedAuthHeader,
		},
		{
			name:    "Malformed authorization header wrong preamble",
			headers: http.Header{"Authorization": []string{"WrongApiKey key123"}},
			xpc:     "",
			err:     ErrMalformedAuthHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			act, err := GetAPIKey(tt.headers)
			if act != tt.xpc {
				t.Errorf("Expected %s. Got %s", tt.xpc, act)
			}
			if err != tt.err {
				t.Errorf("Expected %s. Got %s", tt.err, err)
			}
		})
	}
}

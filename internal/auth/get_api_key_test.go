package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKeyNoAuth(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "")

	got, err := GetAPIKey(header)

	if got != "" && err != ErrNoAuthHeaderIncluded {
		t.Errorf("want: no authorization header included ERROR, got: %v", got)
	}

}

func TestGetAPIKeyMalformed(t *testing.T) {

	wantedErr := errors.New("malformed authorization header")

	tests := []struct {
		input string
	}{
		{
			input: "Basic YWxhZGRpbjpvcGVuc2VzYW1l", // wrong authentication method
		},
		{
			input: "ApiKey", // no valid api key
		},
		{
			input: "apikey", // wrong spelled auth method
		},
	}

	for _, tc := range tests {
		inputHeader := http.Header{}
		inputHeader.Set("Authorization", tc.input)

		got, err := GetAPIKey(inputHeader)

		if err == nil || err.Error() != wantedErr.Error() {
			t.Errorf("want: %v, got: %v", wantedErr, err)
		}

		if got != "" {
			t.Errorf("want: empty string, got: %v", got)
		}
	}

}

func TestGetAPIKeyCorrect(t *testing.T) {

	tests := []struct {
		input  string
		wanted string
	}{
		{
			input:  "ApiKey YWxhZGRpbjpvcGVuc2VzYW1l",
			wanted: "YWxhZGRpbjpvcGVuc2VzYW1l",
		},
	}

	for _, tc := range tests {
		inputHeader := http.Header{}
		inputHeader.Set("Authorization", tc.input)

		got, err := GetAPIKey(inputHeader)

		if err != nil {
			t.Errorf("no error expected, but got %v", err)
		}

		if got != tc.wanted {
			t.Errorf("wanted following ApiKey: %v , but got: %v", tc.wanted, got)
		}

	}

}

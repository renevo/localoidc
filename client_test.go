package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestTokenClientMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		header  string
		mode    oidc.AuthMethod
		invalid bool
	}{
		{
			name: "public",
			body: "client_id=anything",
			mode: oidc.AuthMethodNone,
		},
		{
			name: "empty secret public",
			body: "client_id=anything&client_secret=",
			mode: oidc.AuthMethodNone,
		},
		{
			name: "post",
			body: "client_id=anything&client_secret=arbitrary",
			mode: oidc.AuthMethodPost,
		},
		{
			name:   "basic",
			header: "Basic Y2xpZW50OnNlY3JldA==",
			mode:   oidc.AuthMethodBasic,
		},
		{
			name:   "basic empty secret",
			header: "Basic Y2xpZW50Og==",
			mode:   oidc.AuthMethodNone,
		},
		{
			name:    "malformed basic",
			header:  "Basic bad",
			invalid: true,
		},
		{
			name:    "wrong scheme",
			header:  "Bearer token",
			invalid: true,
		},
		{
			name:    "missing id",
			body:    "client_secret=secret",
			invalid: true,
		},
		{
			name:    "duplicate id",
			body:    "client_id=a&client_id=b",
			invalid: true,
		},
		{
			name:    "conflicting methods",
			header:  "Basic Y2xpZW50OnNlY3JldA==",
			body:    "client_id=client&client_secret=secret",
			invalid: true,
		},
		{
			name:    "assertion",
			body:    "client_id=a&client_assertion=jwt",
			invalid: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			r, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/oauth/token", strings.NewReader(tc.body))
			is.NoErr(err)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			mode, err := tokenClientMode(r)
			is.Equal(err != nil, tc.invalid)
			if err == nil {
				is.Equal(mode, tc.mode)
			}
		})
	}
	is := is.New(t)
	r, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:8080/oauth/token?client_id=query", strings.NewReader(url.Values{"client_id": {"body"}}.Encode()))
	is.NoErr(err)
	_, err = tokenClientMode(r)
	is.True(err != nil)
	is.True(validVerifier(strings.Repeat("a", 43)))
	is.True(!validVerifier(strings.Repeat("a", 42)))
	is.True(!validVerifier(strings.Repeat("a", 129)))
	is.True(!validVerifier(strings.Repeat("a", 42) + "!"))
}

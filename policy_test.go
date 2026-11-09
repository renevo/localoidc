package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/matryer/is"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestLocalCallbackPolicy(t *testing.T) {
	for _, raw := range []string{
		"http://127.0.0.1:1234/callback", "https://localhost/cb?value=ok", "http://[::1]:8080/cb",
	} {
		t.Run(raw, func(t *testing.T) { is.New(t).True(localCallback(raw)) })
	}
	for _, raw := range []string{
		"", "/callback", "//localhost/cb", "javascript:alert(1)", "custom://localhost/cb",
		"http://0.0.0.0/cb", "http://127.0.0.2/cb", "http://localhost.example.com/cb",
		"http://localhost./cb", "http://user@localhost/cb", "http://localhost/cb#fragment",
		"http://localhost/cb#", "http://localhost:0/cb", "http://localhost:65536/cb",
		"http://localhost:/cb", "http://localhost:bad/cb", "http://[::ffff:127.0.0.1]/cb",
		"http://2130706433/cb", "http://127.1/cb", "http://localhost\\@example.com/cb",
		"http://[localhost]/cb", "http://[127.0.0.1]/cb", "http://localhost/cb?invalid=%ZZ",
	} {
		t.Run(raw, func(t *testing.T) { is.New(t).True(!localCallback(raw)) })
	}
	is := is.New(t)
	cfg := defaults()
	cfg.RedirectURIs = []string{"http://localhost:1234/cb"}
	is.True(cfg.callbackAllowed("http://localhost:1234/cb"))
	is.True(!cfg.callbackAllowed("http://localhost:1235/cb"))
	is.True(!cfg.callbackAllowed("http://localhost:1234/cb?extra=1"))
	is.Equal(cfg.address(), "127.0.0.1:8080")
	is.Equal(cfg.issuer(), "http://127.0.0.1:8080")
	is.True(cfg.authorityAllowed("127.0.0.1:8080"))
	for _, authority := range []string{"localhost:8080", "evil.com:8080", "127.0.0.1:8081", "127.0.0.1", "127.0.0.1:08080"} {
		is.True(!cfg.authorityAllowed(authority))
	}
}

func TestConfiguredCallbackPolicy(t *testing.T) {
	for _, raw := range []string{
		"http://localhost:9000/callback",
		"https://app.example.test:8443/callback?tenant=local",
		"https://app.example.test/callback",
		"https://192.0.2.1:8443/callback",
		"https://[2001:db8::1]:8443/callback",
	} {
		t.Run(raw, func(t *testing.T) {
			is := is.New(t)
			cfg := defaults()
			cfg.RedirectURIs = []string{raw}

			is.NoErr(cfg.validate())          // Exact HTTPS destinations and existing loopback callbacks must be configurable.
			is.True(cfg.callbackAllowed(raw)) // A valid explicitly trusted URI must be usable at runtime.
		})
	}

	for _, raw := range []string{
		"",
		"/callback",
		"//app.example.test/callback",
		"https:app.example.test/callback",
		"http://app.example.test/callback",
		"custom://app.example.test/callback",
		"https:///callback",
		"https://user@app.example.test/callback",
		"https://app.example.test/callback#fragment",
		"https://app.example.test/callback#",
		"https://*.example.test/callback",
		"https://app.example.test:/callback",
		"https://app.example.test:0/callback",
		"https://app.example.test:65536/callback",
		"https://app.example.test:bad/callback",
		"https://[app.example.test]/callback",
		"https://[127.0.0.1]/callback",
		"https://[not:ipv6]/callback",
		"https://[fe80::1%25eth0]/callback",
		"https://app.example.test/callback?invalid=%ZZ",
		"https://app.example.test/call%ZZback",
		"https://app.example.test\\@other.example.test/callback",
	} {
		t.Run(raw, func(t *testing.T) {
			is := is.New(t)
			cfg := defaults()
			cfg.RedirectURIs = []string{raw}

			is.True(cfg.validate() != nil)     // An explicit entry must not bypass callback syntax or transport safety.
			is.True(!cfg.callbackAllowed(raw)) // Runtime validation must fail closed even if startup validation was bypassed.
		})
	}
}

func TestExplicitHTTPSCallbackRequiresExactMatch(t *testing.T) {
	is := is.New(t)
	callback := "https://app.example.test:8443/callback?tenant=local"
	cfg := defaults()

	is.True(!cfg.callbackAllowed(callback)) // Default settings must not trust a non-loopback HTTPS hostname.

	cfg.RedirectURIs = []string{callback}

	is.True(cfg.callbackAllowed(callback)) // The entire configured URI is the unit of trust.
	for _, raw := range []string{
		"http://app.example.test:8443/callback?tenant=local",
		"https://other.example.test:8443/callback?tenant=local",
		"https://app.example.test.evil.test:8443/callback?tenant=local",
		"https://app.example.test:9443/callback?tenant=local",
		"https://app.example.test/callback?tenant=local",
		"https://app.example.test:8443/other?tenant=local",
		"https://app.example.test:8443/callback",
		"https://app.example.test:8443/callback?tenant=other",
		"https://app.example.test:8443/callback?tenant=local&extra=1",
		"https://APP.example.test:8443/callback?tenant=local",
		"https://app.example.test:8443/%63allback?tenant=local",
		"http://localhost:9000/callback",
	} {
		t.Run(raw, func(t *testing.T) {
			is.New(t).True(!cfg.callbackAllowed(raw)) // Neither URI normalization nor a trusted host may widen an exact allowlist entry.
		})
	}
}

func TestConfirmationDecisions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		skip    bool
		prompts []string
		confirm bool
		invalid bool
	}{
		{
			name:    "default",
			confirm: true,
		},
		{
			name: "automatic",
			skip: true,
		},
		{
			name:    "none requires interaction",
			prompts: []string{"none"},
			invalid: true,
		},
		{
			name:    "none automatic",
			skip:    true,
			prompts: []string{"none"},
		},
		{
			name:    "forced login",
			skip:    true,
			prompts: []string{"login"},
			confirm: true,
		},
		{
			name:    "forced consent",
			skip:    true,
			prompts: []string{"consent"},
			confirm: true,
		},
		{
			name:    "account",
			skip:    true,
			prompts: []string{"select_account"},
			confirm: true,
		},
		{
			name:    "mixed none",
			skip:    true,
			prompts: []string{"none", "login"},
			invalid: true,
		},
		{
			name:    "unknown",
			prompts: []string{"invalid"},
			invalid: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			confirm, err := needsConfirmation(tc.skip, tc.prompts)
			is.Equal(err != nil, tc.invalid)
			if err == nil {
				is.Equal(confirm, tc.confirm)
			}
		})
	}
}

func TestScopeClaimReleasePreservesTypesAndFalse(t *testing.T) {
	is := is.New(t)
	cfg := defaults()
	cfg.Identity.Claims["email_verified"] = false
	cfg.Identity.Claims["groups"] = []any{"developers", "admins"}
	cfg.Identity.Claims["number"] = json.Number("9007199254740993")
	cfg.Scopes["groups"] = []string{"groups", "number"}
	is.Equal(cfg.claimsFor([]string{"openid"}), map[string]any{"sub": "local-user"})
	is.Equal(cfg.claimsFor([]string{"email"}), map[string]any{
		"sub": "local-user", "email": "developer@localhost", "email_verified": false,
	})
	var info oidc.UserInfo
	cfg.fillUserinfo(&info, []string{"openid", "groups", "email"})
	data, err := json.Marshal(&info)
	is.NoErr(err)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var claims map[string]any
	is.NoErr(decoder.Decode(&claims))
	is.Equal(claims["groups"], []any{"developers", "admins"})
	is.Equal(claims["number"], json.Number("9007199254740993"))
	is.Equal(claims["email_verified"], false)
	_, hasName := claims["name"]
	is.True(!hasName)
}

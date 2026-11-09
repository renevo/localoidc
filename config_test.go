package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/matryer/is"
)

func TestVersionDoesNotLoadRuntimeConfiguration(t *testing.T) {
	is := is.New(t)
	_, err := loadSettings(context.Background(), []string{"--version", "--config", filepath.Join(t.TempDir(), "missing.json")}, []string{
		"HTTP_PORT=invalid", "LOCALOIDC_UNKNOWN=true",
	}, io.Discard)
	is.True(errors.Is(err, errVersionRequested))
}

func TestConfigurationPrecedenceAndTypes(t *testing.T) {
	is := is.New(t)
	path := filepath.Join(t.TempDir(), "localoidc.json")
	is.NoErr(os.WriteFile(path, []byte(`{
		"port": 8123,
		"skip_confirmation": false,
		"identity": {"sub": "test", "claims": {
			"email_verified": false, "groups": ["developers"], "count": 9007199254740993,
			"metadata": {"enabled": true}
		}},
		"scopes": {"openid": [], "custom": ["groups", "count", "metadata", "email_verified"]}
	}`), 0600))
	cfg, err := loadSettings(context.Background(), []string{"--config", path, "--port=8125", "--skip-confirmation=false"}, []string{
		"HTTP_PORT=8124", "LOCALOIDC_SKIP_CONFIRMATION=true",
	}, io.Discard)
	is.NoErr(err)
	is.Equal(cfg.Port, 8125)
	is.Equal(cfg.SkipConfirmation, false)
	is.Equal(cfg.Identity.Subject, "test")
	is.Equal(cfg.Identity.Claims["email_verified"], false)
	is.Equal(cfg.Identity.Claims["groups"], []any{"developers"})
	is.Equal(cfg.Identity.Claims["count"], json.Number("9007199254740993"))
	is.Equal(cfg.Identity.Claims["metadata"], map[string]any{"enabled": true})

	cfg, err = loadSettings(context.Background(), []string{"--config", path}, []string{"HTTP_PORT=8124"}, io.Discard)
	is.NoErr(err)
	is.Equal(cfg.Port, 8124)
	cfg, err = loadSettings(context.Background(), []string{"--config", path}, nil, io.Discard)
	is.NoErr(err)
	is.Equal(cfg.Port, 8123)
	cfg, err = loadSettings(context.Background(), nil, nil, io.Discard)
	is.NoErr(err)
	is.Equal(cfg.Port, 8080)
	is.Equal(cfg.SkipConfirmation, false)
}

func TestHTTPSCallbackConfiguration(t *testing.T) {
	is := is.New(t)
	path := filepath.Join(t.TempDir(), "callbacks.json")
	fileConfig := []byte(`{"redirect_uris":["https://file.example.test:8443/callback"]}`)

	is.NoErr(os.WriteFile(path, fileConfig, 0600)) // The file fixture must provide an explicit custom-host HTTPS callback.

	cfg, err := loadSettings(context.Background(), []string{"--config", path}, nil, io.Discard)

	is.NoErr(err)                                                                   // Custom-host HTTPS callbacks must load through the existing JSON setting.
	is.Equal(cfg.RedirectURIs, []string{"https://file.example.test:8443/callback"}) // Loading must preserve the exact configured URI.

	environment := []string{`LOCALOIDC_REDIRECT_URIS=["https://env.example.test:9443/callback?tenant=local"]`}
	cfg, err = loadSettings(context.Background(), []string{"--config", path}, environment, io.Discard)

	is.NoErr(err)                                                                               // The existing environment setting must also accept custom-host HTTPS callbacks.
	is.Equal(cfg.RedirectURIs, []string{"https://env.example.test:9443/callback?tenant=local"}) // Environment values must replace, not merge with, file callbacks.
	is.True(!cfg.callbackAllowed("https://file.example.test:8443/callback"))                    // An overridden callback must no longer be trusted.

	cfg, err = loadSettings(context.Background(), []string{"--config", path}, []string{"LOCALOIDC_REDIRECT_URIS=[]"}, io.Discard)

	is.NoErr(err)                                                            // An empty environment allowlist must restore the default loopback policy.
	is.True(!cfg.callbackAllowed("https://file.example.test:8443/callback")) // Clearing the list must revoke explicit hostname trust.
	is.True(cfg.callbackAllowed("http://localhost:9000/callback"))           // Clearing the list must retain the original loopback workflow.
}

func TestInvalidConfiguration(t *testing.T) {
	for _, env := range []string{
		"HTTP_PORT=0", "HTTP_PORT=65536", "HTTP_PORT=garbage", "HTTP_ADDRESS=0.0.0.0:8080",
		"LOCALOIDC_SKIP_CONFIRMATION=perhaps", "LOCALOIDC_UNKNOWN=true", "LOCALOIDC_CODE_LIFETIME=0s",
		"LOCALOIDC_TOKEN_LIFETIME=25h", "LOCALOIDC_MAX_TRANSACTIONS=10001",
		`LOCALOIDC_IDENTITY={"sub":"test","claims":{"iss":"fake"}}`,
		`LOCALOIDC_IDENTITY={"sub":"","claims":{}}`,
		`LOCALOIDC_IDENTITY={"sub":"a:b","claims":{}}`,
		`LOCALOIDC_IDENTITY={"sub":"a","claims":{"email_verified":"true"}}`,
		`LOCALOIDC_IDENTITY={"sub":"a","claims":{"name":["bad"]}}`,
		`LOCALOIDC_IDENTITY={"sub":"a","unknown":true}`,
		`LOCALOIDC_SCOPES={"profile":[]}`,
		`LOCALOIDC_SCOPES={"openid":[],"offline_access":[]}`,
		`LOCALOIDC_SCOPES={"openid":[],"custom":["undefined"]}`,
		`LOCALOIDC_REDIRECT_URIS=["http://example.test/callback"]`,
	} {
		t.Run(env, func(t *testing.T) {
			is := is.New(t)
			_, err := loadSettings(context.Background(), nil, []string{env}, io.Discard)
			is.True(err != nil) // Invalid settings must fail startup rather than silently relaxing policy.
		})
	}
	is := is.New(t)
	path := filepath.Join(t.TempDir(), "unknown.json")
	is.NoErr(os.WriteFile(path, []byte(`{"unknown":true}`), 0600))
	_, err := loadSettings(context.Background(), []string{"--config", path}, nil, io.Discard)
	is.True(err != nil)
}

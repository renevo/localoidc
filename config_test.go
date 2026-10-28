package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/matryer/is"
)

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
		`LOCALOIDC_REDIRECT_URIS=["https://example.com/callback"]`,
	} {
		t.Run(env, func(t *testing.T) {
			is := is.New(t)
			_, err := loadSettings(context.Background(), nil, []string{env}, io.Discard)
			is.True(err != nil)
		})
	}
	is := is.New(t)
	path := filepath.Join(t.TempDir(), "unknown.json")
	is.NoErr(os.WriteFile(path, []byte(`{"unknown":true}`), 0600))
	_, err := loadSettings(context.Background(), []string{"--config", path}, nil, io.Discard)
	is.True(err != nil)
}

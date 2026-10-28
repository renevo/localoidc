package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/renevo/config"
)

var errVersionRequested = errors.New("version requested")

type identity struct {
	Subject string         `json:"sub"`
	Claims  map[string]any `json:"claims"`
}

type settings struct {
	Port             int
	SkipConfirmation bool
	Identity         identity
	Scopes           map[string][]string
	RedirectURIs     []string
	RequestLifetime  time.Duration
	CodeLifetime     time.Duration
	TokenLifetime    time.Duration
	MaxTransactions  int
}

func defaults() settings {
	return settings{
		Port: 8080,
		Identity: identity{
			Subject: "local-user",
			Claims: map[string]any{
				"name":               "Local Developer",
				"preferred_username": "developer",
				"email":              "developer@localhost",
				"email_verified":     true,
			},
		},
		Scopes: map[string][]string{
			"openid":  {},
			"profile": {"name", "preferred_username"},
			"email":   {"email", "email_verified"},
		},
		RedirectURIs:    []string{},
		RequestLifetime: 5 * time.Minute,
		CodeLifetime:    time.Minute,
		TokenLifetime:   time.Hour,
		MaxTransactions: 1024,
	}
}

// JSON is a composite-value codec for Bootstrap's underlying configuration library.
// UseNumber preserves integer precision for synthetic custom claims.
type jsonCodec[T any] struct{}

func (jsonCodec[T]) Parse(text string) (any, error) {
	var value T
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("expected one JSON value")
	}
	return value, nil
}

func (jsonCodec[T]) Format(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}

func (jsonCodec[T]) Equal(a, b any) bool { return reflect.DeepEqual(a, b) }

func loadSettings(ctx context.Context, args, environment []string, output io.Writer) (settings, error) {
	cfg := defaults()
	env := make(map[string]string)
	for _, entry := range environment {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	flags := flag.NewFlagSet("localoidc", flag.ContinueOnError)
	flags.SetOutput(output)
	path := flags.String("config", env["LOCALOIDC_CONFIG"], "JSON configuration file (or LOCALOIDC_CONFIG)")
	port := flags.Int("port", cfg.Port, "loopback HTTP port (or HTTP_PORT)")
	skip := flags.Bool("skip-confirmation", false, "automatically approve ordinary requests (or LOCALOIDC_SKIP_CONFIRMATION)")
	showVersion := flags.Bool("version", false, "print build version and exit without starting the server")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if flags.NArg() != 0 {
		return cfg, errors.New("unexpected positional arguments")
	}
	// Build inspection must work even when the runtime configuration is invalid.
	if *showVersion {
		return cfg, errVersionRequested
	}
	set := config.NewSet()
	portSetting := set.Setting("port", cfg.Port, "Loopback HTTP port")
	skipSetting := set.Setting("skip_confirmation", cfg.SkipConfirmation, "Skip ordinary confirmation")
	identitySetting := set.Setting("identity", cfg.Identity, "Synthetic identity", config.WithCodec(jsonCodec[identity]{}))
	scopesSetting := set.Setting("scopes", cfg.Scopes, "Scope claim mappings", config.WithCodec(jsonCodec[map[string][]string]{}))
	redirectSetting := set.Setting("redirect_uris", cfg.RedirectURIs, "Optional exact local callbacks", config.WithCodec(jsonCodec[[]string]{}))
	requestSetting := set.Setting("request_lifetime", cfg.RequestLifetime, "Pending request lifetime")
	codeSetting := set.Setting("code_lifetime", cfg.CodeLifetime, "Authorization code lifetime")
	tokenSetting := set.Setting("token_lifetime", cfg.TokenLifetime, "Token lifetime")
	maxSetting := set.Setting("max_transactions", cfg.MaxTransactions, "Maximum live requests and tokens each")
	fileValues := make(map[string]string)
	if *path != "" {
		data, err := os.ReadFile(*path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		var values map[string]json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil || values == nil {
			return cfg, errors.New("config must be a JSON object")
		}
		for key, value := range values {
			if bytes.HasPrefix(value, []byte(`"`)) {
				var text string
				if err := json.Unmarshal(value, &text); err != nil {
					return cfg, err
				}
				fileValues[key] = text
			} else {
				fileValues[key] = string(value)
			}
		}
	}
	envNames := map[string]string{
		"HTTP_PORT":                   "port",
		"LOCALOIDC_SKIP_CONFIRMATION": "skip_confirmation",
		"LOCALOIDC_IDENTITY":          "identity",
		"LOCALOIDC_SCOPES":            "scopes",
		"LOCALOIDC_REDIRECT_URIS":     "redirect_uris",
		"LOCALOIDC_REQUEST_LIFETIME":  "request_lifetime",
		"LOCALOIDC_CODE_LIFETIME":     "code_lifetime",
		"LOCALOIDC_TOKEN_LIFETIME":    "token_lifetime",
		"LOCALOIDC_MAX_TRANSACTIONS":  "max_transactions",
	}
	envValues := make(map[string]string)
	for key, value := range env {
		if name, ok := envNames[key]; ok {
			envValues[name] = value
		} else if key == "HTTP_ADDRESS" || (strings.HasPrefix(key, "LOCALOIDC_") && key != "LOCALOIDC_CONFIG") {
			return cfg, fmt.Errorf("unsupported environment setting %s", key)
		}
	}
	flagValues := make(map[string]string)
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "port":
			flagValues["port"] = strconv.Itoa(*port)
		case "skip-confirmation":
			flagValues["skip_confirmation"] = strconv.FormatBool(*skip)
		}
	})
	if err := set.Load(ctx, config.ValuesSource("file", fileValues), config.ValuesSource("environment", envValues), config.ValuesSource("flags", flagValues)); err != nil {
		// Configuration errors may contain raw values. Do not expose identities or secrets in startup logs.
		var settingError *config.SettingError
		if errors.As(err, &settingError) {
			if errors.Is(err, config.ErrNotFound) {
				return cfg, fmt.Errorf("unknown configuration setting %q", settingError.Path)
			}
			return cfg, fmt.Errorf("invalid value for configuration setting %q from %s", settingError.Path, settingError.Source)
		}
		return cfg, errors.New("invalid configuration setting, value, or unknown key; check the documented schema")
	}
	// Registration fixes each setting's type; retrieval cannot fail after successful loading.
	cfg.Port, _ = config.Value[int](portSetting)
	cfg.SkipConfirmation, _ = config.Value[bool](skipSetting)
	cfg.Identity, _ = config.Value[identity](identitySetting)
	cfg.Scopes, _ = config.Value[map[string][]string](scopesSetting)
	cfg.RedirectURIs, _ = config.Value[[]string](redirectSetting)
	cfg.RequestLifetime, _ = config.Value[time.Duration](requestSetting)
	cfg.CodeLifetime, _ = config.Value[time.Duration](codeSetting)
	cfg.TokenLifetime, _ = config.Value[time.Duration](tokenSetting)
	cfg.MaxTransactions, _ = config.Value[int](maxSetting)
	return cfg, cfg.validate()
}

var reservedClaims = strings.Fields("iss sub aud exp nbf iat jti nonce auth_time acr amr azp at_hash c_hash s_hash sid client_id scope scopes act cnf")

func (s settings) validate() error {
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if strings.TrimSpace(s.Identity.Subject) == "" || strings.Contains(s.Identity.Subject, ":") {
		// The library's opaque bearer format uses ':' to separate token ID and subject.
		return errors.New("identity sub must be nonempty and cannot contain ':'")
	}
	for _, claim := range reservedClaims {
		if _, ok := s.Identity.Claims[claim]; ok {
			return fmt.Errorf("identity claims cannot override protocol claim %s", claim)
		}
	}
	// Validate standard claim types with the protocol library as well as preserving custom JSON types.
	if err := validateStandardClaims(s.Identity.Claims); err != nil {
		return err
	}
	if _, ok := s.Scopes["openid"]; !ok {
		return errors.New("scopes must include openid")
	}
	for scope, claims := range s.Scopes {
		if !validScope(scope) || scope == "offline_access" {
			return errors.New("scope names must be nonempty OAuth scope tokens; offline_access is unsupported")
		}
		for _, claim := range claims {
			if _, exists := s.Identity.Claims[claim]; !exists {
				return fmt.Errorf("scope %s references an undefined claim", scope)
			}
		}
	}
	for _, uri := range s.RedirectURIs {
		if !localCallback(uri) {
			return errors.New("redirect_uris must contain only valid local HTTP(S) callbacks")
		}
	}
	for _, lifetime := range []time.Duration{s.RequestLifetime, s.CodeLifetime, s.TokenLifetime} {
		if lifetime < time.Second || lifetime > 24*time.Hour {
			return errors.New("lifetimes must be between 1s and 24h")
		}
	}
	if s.MaxTransactions < 1 || s.MaxTransactions > 10000 {
		return errors.New("max_transactions must be between 1 and 10000")
	}
	return nil
}

func validScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, c := range scope {
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func (s settings) address() string { return "127.0.0.1:" + strconv.Itoa(s.Port) }
func (s settings) issuer() string  { return "http://" + s.address() }

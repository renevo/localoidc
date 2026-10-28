package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

//go:embed login.html
var loginHTML string

var loginTemplate = template.Must(template.New("login").Parse(loginHTML))

//go:embed continue.html
var continueHTML string

var continueTemplate = template.Must(template.New("continue").Parse(continueHTML))

//go:embed error.html
var errorHTML string

var errorTemplate = template.Must(template.New("error").Parse(errorHTML))

//go:embed styles.css
var stylesCSS string

type server struct {
	cfg      settings
	storage  *storage
	provider *op.Provider
}

func newServer(cfg settings) (*server, error) {
	store, err := newStorage(cfg)
	if err != nil {
		return nil, err
	}
	var key [32]byte
	copy(key[:], randomBytes(len(key)))
	scopes := make([]string, 0, len(cfg.Scopes))
	for scope := range cfg.Scopes {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	claims := []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "azp"}
	for name := range cfg.Identity.Claims {
		claims = append(claims, name)
	}
	sort.Strings(claims)
	provider, err := op.NewProvider(&op.Config{
		CryptoKey:       key,
		CodeMethodS256:  true,
		AuthMethodPost:  true,
		SupportedScopes: scopes,
		SupportedClaims: claims,
	}, store, op.StaticIssuer(cfg.issuer()), op.WithAllowInsecure(), op.WithCORSOptions(nil))
	if err != nil {
		return nil, err
	}
	return &server{
		cfg:      cfg,
		storage:  store,
		provider: provider,
	}, nil
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) { op.Keys(w, r, s.storage) })
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) { op.Userinfo(w, r, s.provider) })
	mux.HandleFunc("POST /userinfo", func(w http.ResponseWriter, r *http.Request) { op.Userinfo(w, r, s.provider) })
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.confirm)
	mux.HandleFunc("GET /styles.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write([]byte(stylesCSS))
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("localoidc — DEVELOPMENT ONLY. No authentication.\nIssuer: " + s.cfg.issuer() + "\nConfigure your local OIDC client with this issuer and any nonempty client ID.\n"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		// Chromium nulls navigation POST origins under no-referrer. Preserve the
		// same-origin form Origin without sending authorization URLs to callbacks
		// on another origin, including callbacks using a different loopback port.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if !s.cfg.authorityAllowed(r.Host) || (r.URL.IsAbs() && r.URL.Host != s.cfg.address()) {
			http.Error(w, "use the canonical loopback issuer", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		ctx := op.ContextWithIssuer(r.Context(), s.cfg.issuer())
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Use the library's discovery model but narrow its broad defaults to precisely
// the routes/flows wired above. Its default router advertises unsupported extras.
func (s *server) discovery(w http.ResponseWriter, r *http.Request) {
	doc := op.CreateDiscoveryConfig(r.Context(), s.provider, s.storage)
	doc.ResponseTypesSupported = []string{"code"}
	doc.ResponseModesSupported = []string{"query"}
	doc.GrantTypesSupported = []oidc.GrantType{oidc.GrantTypeCode}
	doc.IntrospectionEndpoint = ""
	doc.IntrospectionEndpointAuthMethodsSupported = nil
	doc.IntrospectionEndpointAuthSigningAlgValuesSupported = nil
	doc.RevocationEndpoint = ""
	doc.RevocationEndpointAuthMethodsSupported = nil
	doc.RevocationEndpointAuthSigningAlgValuesSupported = nil
	doc.EndSessionEndpoint = ""
	doc.DeviceAuthorizationEndpoint = ""
	doc.CheckSessionIframe = ""
	op.Discover(w, doc)
}

func singleValues(values url.Values) bool {
	for _, entries := range values {
		if len(entries) != 1 {
			return false
		}
	}
	return true
}

func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	request, err := op.ParseAuthorizeRequest(r, s.provider.Decoder())
	if err != nil || !singleValues(r.Form) {
		http.Error(w, "invalid authorization parameters", http.StatusBadRequest)
		return
	}
	// This runs before any library error can redirect. Arbitrary client IDs do
	// not authorize arbitrary destinations, including destinations for errors.
	if !s.cfg.callbackAllowed(request.RedirectURI) {
		http.Error(w, "redirect_uri must be an allowed local HTTP(S) callback", http.StatusBadRequest)
		return
	}
	ctx := context.WithValue(r.Context(), requestContextKey{}, clientContext{redirect: request.RedirectURI})
	r = r.WithContext(ctx)
	invalid := func(message string) {
		op.AuthRequestError(w, r, request, oidc.ErrInvalidRequest().WithDescription("%s", message), s.provider)
	}
	if request.ClientID == "" {
		invalid("client_id is required")
		return
	}
	if !slices.Contains(request.Scopes, "openid") {
		invalid("openid scope is required")
		return
	}
	for _, scope := range request.Scopes {
		if _, ok := s.cfg.Scopes[scope]; !ok {
			op.AuthRequestError(w, r, request, oidc.ErrInvalidScope().WithDescription("unsupported scope"), s.provider)
			return
		}
	}
	if request.ResponseType != oidc.ResponseTypeCode || (request.ResponseMode != "" && request.ResponseMode != oidc.ResponseModeQuery) {
		invalid("only response_type code with query response mode is supported")
		return
	}
	if r.Form.Get("request") != "" || r.Form.Get("request_uri") != "" || r.Form.Get("claims") != "" {
		invalid("request objects, request_uri and claims parameters are unsupported")
		return
	}
	if request.CodeChallenge != "" {
		challenge, err := base64.RawURLEncoding.DecodeString(request.CodeChallenge)
		if err != nil || len(challenge) != 32 || len(request.CodeChallenge) != 43 || request.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
			invalid("PKCE requires an S256 challenge")
			return
		}
	} else if request.CodeChallengeMethod != "" {
		invalid("code_challenge is required with code_challenge_method")
		return
	}
	if _, err := needsConfirmation(s.cfg.SkipConfirmation, request.Prompt); err != nil {
		op.AuthRequestError(w, r, request, err, s.provider)
		return
	}
	op.Authorize(w, r, s.provider)
}

// Determine client mode per exchange, not through a registration database.
// The library still enforces the stored client ID, exact redirect and PKCE.
func tokenClientMode(r *http.Request) (oidc.AuthMethod, error) {
	if r.URL.RawQuery != "" || r.ParseForm() != nil || !singleValues(r.PostForm) {
		return "", errors.New("invalid token form")
	}
	if r.PostForm.Has("client_assertion") || r.PostForm.Has("client_assertion_type") {
		return "", errors.New("client assertions are unsupported")
	}
	if len(r.Header.Values("Authorization")) > 1 {
		return "", errors.New("multiple authorization headers")
	}
	if r.Header.Get("Authorization") != "" {
		id, secret, ok := r.BasicAuth()
		if !ok || r.PostForm.Has("client_id") || r.PostForm.Has("client_secret") {
			return "", errors.New("malformed or conflicting client authentication")
		}
		id, err := url.QueryUnescape(id)
		if err != nil || id == "" {
			return "", errors.New("invalid Basic client ID")
		}
		secret, err = url.QueryUnescape(secret)
		if err != nil {
			return "", errors.New("invalid Basic client secret")
		}
		if secret == "" {
			return oidc.AuthMethodNone, nil
		}
		return oidc.AuthMethodBasic, nil
	}
	if r.PostForm.Get("client_id") == "" {
		return "", errors.New("client_id is required")
	}
	if r.PostForm.Get("client_secret") == "" {
		return oidc.AuthMethodNone, nil
	}
	return oidc.AuthMethodPost, nil
}

func validVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, c := range verifier {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	return true
}

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	method, err := tokenClientMode(r)
	if err != nil {
		op.RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("invalid or conflicting client authentication"), nil)
		return
	}
	if r.PostForm.Get("grant_type") != string(oidc.GrantTypeCode) {
		op.RequestError(w, r, oidc.ErrUnsupportedGrantType(), nil)
		return
	}
	if verifier := r.PostForm.Get("code_verifier"); verifier != "" && !validVerifier(verifier) {
		op.RequestError(w, r, oidc.ErrInvalidRequest().WithDescription("invalid PKCE verifier syntax"), nil)
		return
	}
	ctx := context.WithValue(r.Context(), requestContextKey{}, clientContext{method: method})
	op.CodeExchange(w, r.WithContext(ctx), s.provider)
}

func confirmationCookie(id string) string { return "localoidc_" + id }

func confirmationError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = errorTemplate.Execute(w, struct {
		Title   string
		Message string
	}{Title: title, Message: message})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	request, err := s.storage.AuthRequestByID(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		confirmationError(w, http.StatusBadRequest, "Sign-in request unavailable", "This login request expired, was already used, or is no longer available.")
		return
	}
	a := request.(authRequest)
	if a.approved {
		op.AuthResponse(a, s.provider, w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     confirmationCookie(a.id),
		Value:    a.csrf,
		Path:     "/login",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.cfg.RequestLifetime.Seconds()),
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, struct {
		ID       string
		CSRF     string
		Subject  string
		Name     string
		Email    string
		Client   string
		Scopes   string
		Redirect string
	}{
		ID:       a.id,
		CSRF:     a.csrf,
		Subject:  a.subject,
		Name:     displayClaim(s.cfg.Identity.Claims, "name"),
		Email:    displayClaim(s.cfg.Identity.Claims, "email"),
		Client:   a.ClientID,
		Scopes:   strings.Join(a.Scopes, " "),
		Redirect: a.RedirectURI,
	})
}

func displayClaim(claims map[string]any, name string) string {
	value, _ := claims[name].(string)
	return value
}

func (s *server) confirm(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.ParseForm() != nil || !singleValues(r.PostForm) {
		confirmationError(w, http.StatusBadRequest, "Unable to confirm sign-in", "The confirmation form is invalid. No identity was confirmed.")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.cfg.issuer() {
		confirmationError(w, http.StatusForbidden, "Unable to confirm sign-in", "The confirmation did not come from this local issuer. No identity was confirmed.")
		return
	}
	id, csrf := r.PostForm.Get("id"), r.PostForm.Get("csrf")
	cookie, err := r.Cookie(confirmationCookie(id))
	if err != nil || csrf == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(csrf)) != 1 {
		confirmationError(w, http.StatusForbidden, "Unable to confirm sign-in", "The confirmation state is missing or invalid. Cookies must be enabled to confirm your local identity.")
		return
	}
	a, err := s.storage.confirm(id, csrf)
	if err != nil {
		confirmationError(w, http.StatusBadRequest, "Sign-in request unavailable", "This login request expired, was already used, or is no longer available.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     confirmationCookie(id),
		Path:     "/login",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	// Chromium applies the form's CSP to the entire POST redirect chain. Commit
	// a same-origin document first, then navigate to the approved GET /login.
	// That GET issues the callback redirect without relaxing form-action 'self'.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = continueTemplate.Execute(w, a.id)
}

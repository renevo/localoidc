package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestAuthorizeCallbackPolicy(t *testing.T) {
	callback := "https://app.example.test:8443/callback?tenant=local"
	for _, tc := range []struct {
		name      string
		allowlist []string
		redirect  string
		allowed   bool
	}{
		{
			name:     "custom hostname rejected by default",
			redirect: callback,
		},
		{
			name:      "exact HTTPS entry accepted",
			allowlist: []string{callback},
			redirect:  callback,
			allowed:   true,
		},
		{
			name:      "other path rejected",
			allowlist: []string{callback},
			redirect:  "https://app.example.test:8443/other?tenant=local",
		},
		{
			name:      "HTTP downgrade rejected",
			allowlist: []string{callback},
			redirect:  "http://app.example.test:8443/callback?tenant=local",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			cfg := defaults()
			cfg.RedirectURIs = tc.allowlist
			app, err := newServer(cfg)
			is.NoErr(err) // The endpoint fixture must use the real provider and application callback policy.

			// An invalid scope normally redirects an error to the callback. Untrusted
			// callbacks must be rejected before the provider can produce that redirect.
			query := url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {tc.redirect},
				"response_type": {"code"},
				"scope":         {"openid unsupported"},
				"state":         {"test-state"},
			}
			request := httptest.NewRequest(http.MethodGet, cfg.issuer()+"/authorize?"+query.Encode(), nil)
			response := httptest.NewRecorder()

			app.handler().ServeHTTP(response, request)

			if !tc.allowed {
				is.Equal(response.Code, http.StatusBadRequest)  // Untrusted destinations must fail locally before protocol error handling.
				is.Equal(response.Header().Get("Location"), "") // Neither codes nor errors may be redirected to an untrusted callback.
				is.Equal(len(app.storage.requests), 0)          // Rejected destinations must not create pending authorization state.
				return
			}

			is.Equal(response.Code, http.StatusFound) // A configured HTTPS callback must reach normal provider error handling.
			location, err := url.Parse(response.Header().Get("Location"))
			is.NoErr(err)                                                                                         // The protocol error response must have a parseable redirect destination.
			is.Equal(location.Scheme+"://"+location.Host+location.Path, "https://app.example.test:8443/callback") // Error redirects must retain the trusted HTTPS authority and path.
			is.Equal(location.Query().Get("tenant"), "local")                                                     // Existing callback query parameters must be preserved.
			is.Equal(location.Query().Get("error"), "invalid_scope")                                              // Callback opt-in must not bypass normal scope validation.
			is.Equal(location.Query().Get("state"), "test-state")                                                 // Error redirects must preserve the requesting client's state.
		})
	}
}

func TestExplicitHTTPSCallbackCodeExchange(t *testing.T) {
	callback := "https://app.example.test:8443/callback?tenant=local"
	for _, exchangeCallback := range []string{callback, "https://app.example.test:8443/other?tenant=local"} {
		t.Run(exchangeCallback, func(t *testing.T) {
			is := is.New(t)
			cfg := defaults()
			cfg.SkipConfirmation = true
			cfg.RedirectURIs = []string{callback}
			app, err := newServer(cfg)
			is.NoErr(err) // The exchange fixture must exercise the real authorization-code provider.
			handler := app.handler()
			query := url.Values{
				"client_id":     {"test-client"},
				"redirect_uri":  {callback},
				"response_type": {"code"},
				"scope":         {"openid email"},
				"state":         {"test-state"},
				"nonce":         {"test-nonce"},
			}
			request := httptest.NewRequest(http.MethodGet, cfg.issuer()+"/authorize?"+query.Encode(), nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			is.Equal(response.Code, http.StatusFound) // Authorization must route the trusted request to the local login handler.
			loginURL := response.Header().Get("Location")
			is.True(strings.HasPrefix(loginURL, "/login?id=")) // Only a local login continuation may be followed by this fixture.

			// Even automatic approval uses the login continuation to issue the code.
			// Dispatch it in-process without resolving or contacting the callback host.
			request = httptest.NewRequest(http.MethodGet, cfg.issuer()+loginURL, nil)
			response = httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			is.Equal(response.Code, http.StatusFound) // Automatic approval must issue a code for the exact trusted HTTPS callback.
			location, err := url.Parse(response.Header().Get("Location"))
			is.NoErr(err)                                                                                         // The authorization response must contain a parseable callback URI.
			is.Equal(location.Scheme+"://"+location.Host+location.Path, "https://app.example.test:8443/callback") // Code redirects must preserve the configured HTTPS authority and path.
			is.Equal(location.Query().Get("tenant"), "local")                                                     // Authorization must preserve the callback's existing query.
			is.Equal(location.Query().Get("state"), "test-state")                                                 // The callback must bind the result to the original client state.
			code := location.Query().Get("code")
			is.True(code != "") // A successful authorization must return a redeemable code rather than an error.

			form := url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"test-client"},
				"client_secret": {"local-secret"},
				"code":          {code},
				"redirect_uri":  {exchangeCallback},
			}
			request = httptest.NewRequest(http.MethodPost, cfg.issuer()+"/oauth/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response = httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if exchangeCallback != callback {
				is.Equal(response.Code, http.StatusBadRequest) // Trusting an HTTPS hostname must not weaken the code's exact redirect binding.
				return
			}

			is.Equal(response.Code, http.StatusOK) // The code must exchange successfully when the original exact callback is supplied.
			var tokens struct {
				IDToken     string `json:"id_token"`
				AccessToken string `json:"access_token"`
			}
			is.NoErr(json.Unmarshal(response.Body.Bytes(), &tokens)) // A successful exchange must return a valid token response.
			is.True(tokens.IDToken != "")                            // The trusted callback flow must produce the identity token consumed by OIDC clients.
			is.True(tokens.AccessToken != "")                        // The normal UserInfo access token must remain available.
		})
	}
}

func TestLoginReferrerPolicyPreservesSameOrigin(t *testing.T) {
	is := is.New(t)
	cfg := defaults()
	now := time.Now()
	store := testStorage(cfg, &now)
	a := pendingRequest(t, store)
	app := &server{
		cfg:     cfg,
		storage: store,
	}
	request := httptest.NewRequest(http.MethodGet, cfg.issuer()+"/login?id="+a.id, nil)
	response := httptest.NewRecorder()
	app.handler().ServeHTTP(response, request)

	is.Equal(response.Code, http.StatusOK)
	// This policy preserves the form's Origin and suppresses Referer entirely
	// for foreign callbacks; no-referrer breaks Chromium navigation POSTs.
	is.Equal(response.Header().Get("Referrer-Policy"), "same-origin")
	is.Equal(response.Header().Get("Content-Security-Policy"), "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
}

func TestConfirmationCommitsDocumentBeforeCallbackNavigation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		origin     string
		csrf       string
		cookie     string
		wantStatus int
	}{
		{
			name:       "same-origin confirmation",
			origin:     defaults().issuer(),
			wantStatus: http.StatusOK,
		},
		{
			name:       "confirmation without origin header",
			wantStatus: http.StatusOK,
		},
		{
			name:       "foreign origin",
			origin:     "http://localhost:9000",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "opaque origin even with same-origin fetch metadata",
			origin:     "null",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing cookie",
			cookie:     "missing",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "mismatched cookie",
			cookie:     "wrong",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "matching forged cookie and form",
			cookie:     "wrong",
			csrf:       "wrong",
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := is.New(t)
			cfg := defaults()
			now := time.Now()
			store := testStorage(cfg, &now)
			a := pendingRequest(t, store)
			app := &server{
				cfg:     cfg,
				storage: store,
			}
			csrf := a.csrf
			if tc.csrf != "" {
				csrf = tc.csrf
			}
			form := url.Values{
				"id":   {a.id},
				"csrf": {csrf},
			}
			request := httptest.NewRequest(http.MethodPost, cfg.issuer()+"/login", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Sec-Fetch-Site", "same-origin")
			if tc.cookie != "missing" {
				cookie := a.csrf
				if tc.cookie != "" {
					cookie = tc.cookie
				}
				request.AddCookie(&http.Cookie{
					Name:  confirmationCookie(a.id),
					Value: cookie,
				})
			}
			response := httptest.NewRecorder()
			app.confirm(response, request)

			is.Equal(response.Code, tc.wantStatus)
			stored, err := store.AuthRequestByID(context.Background(), a.id)
			is.NoErr(err)
			is.Equal(stored.Done(), tc.wantStatus == http.StatusOK)
			is.Equal(len(store.codes), 0) // The continuation GET, not the POST, issues the code.
			is.Equal(response.Header().Get("Location"), "")
			if tc.wantStatus != http.StatusOK {
				is.Equal(response.Header().Get("Content-Type"), "text/html; charset=utf-8")
				is.True(strings.Contains(response.Body.String(), "Return to your application and start signing in again."))
				return
			}

			is.Equal(response.Header().Get("Content-Type"), "text/html; charset=utf-8")
			body := response.Body.String()
			is.True(strings.Contains(body, `http-equiv="refresh" content="0;url=/login?id=`+a.id+`"`))
			is.True(strings.Contains(body, `href="/login?id=`+a.id+`"`))
			is.True(!strings.Contains(body, a.RedirectURI))
			is.Equal(stored.(authRequest).csrf, "")
			cookies := response.Result().Cookies()
			is.Equal(len(cookies), 1)
			is.Equal(cookies[0].Name, confirmationCookie(a.id))
			is.Equal(cookies[0].MaxAge, -1)
		})
	}
}

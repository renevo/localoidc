package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"
)

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
	is.Equal(response.Header().Get("Content-Security-Policy"), "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
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

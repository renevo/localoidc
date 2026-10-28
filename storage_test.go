package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matryer/is"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// Storage logic does not need RSA generation. Tests control time explicitly.
func testStorage(cfg settings, now *time.Time) *storage {
	return &storage{
		cfg:      cfg,
		requests: make(map[string]authRequest),
		codes:    make(map[string]string),
		tokens:   make(map[string]accessToken),
		now:      func() time.Time { return *now },
	}
}

func pendingRequest(t *testing.T, store *storage) authRequest {
	t.Helper()
	request, err := store.CreateAuthRequest(context.Background(), &oidc.AuthRequest{
		ClientID:            "test-client",
		RedirectURI:         "http://localhost:9000/callback",
		Scopes:              []string{"openid", "email"},
		Nonce:               "test-nonce",
		State:               "state",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: oidc.CodeChallengeMethodS256,
		ResponseType:        oidc.ResponseTypeCode,
	}, "ignored")
	is.New(t).NoErr(err)
	return request.(authRequest)
}

func TestConfirmationIsOneTimeAndExpires(t *testing.T) {
	is := is.New(t)
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	store := testStorage(defaults(), &now)
	a := pendingRequest(t, store)
	_, err := store.confirm(a.id, "wrong")
	is.True(err != nil)
	approved, err := store.confirm(a.id, a.csrf)
	is.NoErr(err)
	is.True(approved.Done())
	is.True(!a.Done()) // Returned snapshots are not modified by later operations.
	is.Equal(approved.GetAuthTime(), now)
	_, err = store.confirm(a.id, a.csrf)
	is.True(err != nil)
	a = pendingRequest(t, store)
	now = now.Add(store.cfg.RequestLifetime)
	_, err = store.confirm(a.id, a.csrf)
	is.True(err != nil)
	is.Equal(len(store.requests), 0)
}

func TestCodeConsumptionConcurrentAndBindingsPreserved(t *testing.T) {
	is := is.New(t)
	now := time.Now()
	store := testStorage(defaults(), &now)
	a := pendingRequest(t, store)
	is.True(store.SaveAuthCode(context.Background(), a.id, "premature") != nil)
	_, err := store.confirm(a.id, a.csrf)
	is.NoErr(err)
	is.NoErr(store.SaveAuthCode(context.Background(), a.id, "code"))
	is.True(store.SaveAuthCode(context.Background(), a.id, "second-code") != nil)
	_, err = store.AuthRequestByID(context.Background(), a.id)
	is.True(err != nil) // Refreshing Login cannot mint another grant.
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			request, err := store.AuthRequestByCode(context.Background(), "code")
			if err == nil {
				successes.Add(1)
				// These bindings are returned intact to the library for validation.
				check := is.New(t)
				check.Equal(request.GetClientID(), "test-client")
				check.Equal(request.GetRedirectURI(), "http://localhost:9000/callback")
				check.Equal(request.GetNonce(), "test-nonce")
				check.Equal(request.GetCodeChallenge(), &oidc.CodeChallenge{
					Challenge: "challenge",
					Method:    oidc.CodeChallengeMethodS256,
				})
			}
		})
	}
	group.Wait()
	is.Equal(successes.Load(), int32(1))
	is.Equal(len(store.codes), 0)
	is.Equal(len(store.requests), 0)
	is.NoErr(store.DeleteAuthRequest(context.Background(), a.id))
}

func TestExpiryCapacityAndLiveUserinfo(t *testing.T) {
	is := is.New(t)
	now := time.Now()
	cfg := defaults()
	cfg.MaxTransactions = 1
	store := testStorage(cfg, &now)
	a := pendingRequest(t, store)
	_, err := store.CreateAuthRequest(context.Background(), &oidc.AuthRequest{}, "")
	is.True(err != nil)
	_, err = store.confirm(a.id, a.csrf)
	is.NoErr(err)
	is.NoErr(store.SaveAuthCode(context.Background(), a.id, "code"))
	now = now.Add(cfg.CodeLifetime)
	_, err = store.AuthRequestByCode(context.Background(), "code")
	is.True(err != nil)
	a = pendingRequest(t, store) // Expired entries free capacity.
	id, _, err := store.CreateAccessToken(context.Background(), a)
	is.NoErr(err)
	_, _, err = store.CreateAccessToken(context.Background(), a)
	is.True(err != nil)
	var info oidc.UserInfo
	is.NoErr(store.SetUserinfoFromToken(context.Background(), &info, id, a.subject, ""))
	is.Equal(info.Subject, cfg.Identity.Subject)
	is.Equal(info.Claims["email"], cfg.Identity.Claims["email"])
	is.True(store.SetUserinfoFromToken(context.Background(), &info, id, "other-subject", "") != nil)
	is.True(store.SetUserinfoFromToken(context.Background(), &info, "not-issued", a.subject, "") != nil)
	now = now.Add(cfg.TokenLifetime)
	is.True(store.SetUserinfoFromToken(context.Background(), &info, id, a.subject, "") != nil)
	_, _, err = store.CreateAccessToken(context.Background(), a)
	is.NoErr(err)
	is.Equal(len(store.tokens), 1)
}

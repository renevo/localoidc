package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

var errTransaction = errors.New("transaction is missing, expired, or already used")

type authRequest struct {
	*oidc.AuthRequest
	id       string
	subject  string
	csrf     string
	expires  time.Time
	authTime time.Time
	approved bool
	code     string
}

func (a authRequest) GetID() string                      { return a.id }
func (a authRequest) GetACR() string                     { return "" }
func (a authRequest) GetAMR() []string                   { return nil } // No authentication took place.
func (a authRequest) GetAudience() []string              { return []string{a.ClientID} }
func (a authRequest) GetAuthTime() time.Time             { return a.authTime }
func (a authRequest) GetClientID() string                { return a.ClientID }
func (a authRequest) GetNonce() string                   { return a.Nonce }
func (a authRequest) GetRedirectURI() string             { return a.RedirectURI }
func (a authRequest) GetResponseType() oidc.ResponseType { return a.ResponseType }
func (a authRequest) GetResponseMode() oidc.ResponseMode { return a.ResponseMode }
func (a authRequest) GetScopes() []string                { return a.Scopes }
func (a authRequest) GetState() string                   { return a.State }
func (a authRequest) GetSubject() string                 { return a.subject }
func (a authRequest) Done() bool                         { return a.approved }
func (a authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.CodeChallenge,
		Method:    a.CodeChallengeMethod,
	}
}

type accessToken struct {
	subject string
	scopes  []string
	expires time.Time
}

type signingKey struct {
	key *rsa.PrivateKey
	id  string
}

func (k signingKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k signingKey) Algorithm() jose.SignatureAlgorithm          { return jose.RS256 }
func (k signingKey) Key() any                                    { return k.key }
func (k signingKey) ID() string                                  { return k.id }
func (k signingKey) Use() string                                 { return "sig" }

// The public key adapter prevents private key material reaching JWKS.
type publicKey struct{ signingKey }

func (k publicKey) Key() any { return &k.key.PublicKey }

type requestContextKey struct{}
type clientContext struct {
	redirect string
	method   oidc.AuthMethod
}

type storage struct {
	cfg      settings
	key      signingKey
	mu       sync.Mutex
	requests map[string]authRequest
	codes    map[string]string
	tokens   map[string]accessToken
	now      func() time.Time
}

var _ op.Storage = (*storage)(nil)
var _ op.CanSetUserinfoFromRequest = (*storage)(nil)

func newStorage(cfg settings) (*storage, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &storage{
		cfg: cfg,
		key: signingKey{
			key: key,
			id:  randomID(),
		},
		requests: make(map[string]authRequest),
		codes:    make(map[string]string),
		tokens:   make(map[string]accessToken),
		now:      time.Now,
	}, nil
}

func randomID() string {
	return base64.RawURLEncoding.EncodeToString(randomBytes(32))
}

func randomBytes(size int) []byte {
	value := make([]byte, size)
	// crypto/rand.Read never returns an error on the supported Go toolchain.
	_, _ = rand.Read(value)
	return value
}

// Called only under mu. Expired entries are removed before every insertion;
// capacity is a hard limit rather than evicting valid transactions or tokens.
func (s *storage) prune() {
	now := s.now()
	for id, request := range s.requests {
		if !now.Before(request.expires) {
			delete(s.codes, request.code)
			delete(s.requests, id)
		}
	}
	for id, token := range s.tokens {
		if !now.Before(token.expires) {
			delete(s.tokens, id)
		}
	}
}

func (s *storage) CreateAuthRequest(_ context.Context, request *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	confirm, err := needsConfirmation(s.cfg.SkipConfirmation, request.Prompt)
	if err != nil {
		return nil, err
	}
	a := authRequest{
		AuthRequest: request,
		id:          randomID(),
		subject:     s.cfg.Identity.Subject,
		csrf:        randomID(),
		approved:    !confirm,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if len(s.requests) >= s.cfg.MaxTransactions {
		return nil, errors.New("too many pending transactions")
	}
	a.expires = s.now().Add(s.cfg.RequestLifetime)
	if a.approved {
		a.authTime = s.now()
	}
	s.requests[a.id] = a
	return a, nil
}

func (s *storage) AuthRequestByID(_ context.Context, id string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	a, ok := s.requests[id]
	if !ok || a.code != "" {
		return nil, errTransaction
	}
	return a, nil // A value snapshot; no mutable stored record escapes the lock.
}

func (s *storage) confirm(id, csrf string) (authRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	a, ok := s.requests[id]
	if !ok || a.approved || subtle.ConstantTimeCompare([]byte(a.csrf), []byte(csrf)) != 1 {
		return authRequest{}, errTransaction
	}
	a.approved = true
	a.authTime = s.now()
	a.csrf = ""
	s.requests[id] = a
	return a, nil
}

func (s *storage) SaveAuthCode(_ context.Context, id, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	a, ok := s.requests[id]
	if !ok || !a.approved || a.code != "" {
		return errTransaction
	}
	a.code = code
	a.expires = s.now().Add(s.cfg.CodeLifetime)
	s.requests[id] = a
	s.codes[code] = id
	return nil
}

func (s *storage) AuthRequestByCode(_ context.Context, code string) (op.AuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	id, ok := s.codes[code]
	if !ok {
		return nil, errTransaction
	}
	a := s.requests[id]
	// Consume before returning: the library validates PKCE/client/redirect after
	// this lookup. Failed exchanges burn the code; concurrent redemptions cannot
	// both mint tokens. Never restore a code after a failed validation.
	delete(s.codes, code)
	delete(s.requests, id)
	return a, nil
}

func (s *storage) DeleteAuthRequest(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.requests[id]; ok {
		delete(s.codes, a.code)
		delete(s.requests, id)
	}
	return nil
}

func (s *storage) CreateAccessToken(_ context.Context, request op.TokenRequest) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune()
	if len(s.tokens) >= s.cfg.MaxTransactions {
		return "", time.Time{}, errors.New("too many live tokens")
	}
	id := randomID()
	expires := s.now().Add(s.cfg.TokenLifetime)
	s.tokens[id] = accessToken{
		subject: request.GetSubject(),
		scopes:  append([]string(nil), request.GetScopes()...),
		expires: expires,
	}
	return id, expires, nil
}

func (s *storage) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	if id == "" {
		return nil, oidc.ErrInvalidClient()
	}
	data, _ := ctx.Value(requestContextKey{}).(clientContext)
	return client{
		id:       id,
		redirect: data.redirect,
		method:   data.method,
		cfg:      s.cfg,
	}, nil
}

func (s *storage) AuthorizeClientIDSecret(_ context.Context, id, _ string) error {
	if id == "" {
		return oidc.ErrInvalidClient()
	}
	return nil // Deliberately accepts any secret; this is not client authentication.
}

func (s *storage) SetUserinfoFromRequest(_ context.Context, info *oidc.UserInfo, _ op.IDTokenRequest, scopes []string) error {
	s.cfg.fillUserinfo(info, scopes)
	return nil
}

func (s *storage) SetUserinfoFromToken(_ context.Context, info *oidc.UserInfo, id, subject, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[id]
	if !ok || !s.now().Before(token.expires) || token.subject != subject {
		return oidc.ErrAccessDenied().WithDescription("access token is expired or invalid")
	}
	s.cfg.fillUserinfo(info, token.scopes)
	return nil
}

func (s *storage) SigningKey(context.Context) (op.SigningKey, error) { return s.key, nil }
func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}
func (s *storage) KeySet(context.Context) ([]op.Key, error) { return []op.Key{publicKey{s.key}}, nil }
func (s *storage) Health(context.Context) error             { return nil }

// Required library hooks for features localoidc intentionally does not expose.
func (*storage) CreateAccessAndRefreshTokens(context.Context, op.TokenRequest, string) (string, string, time.Time, error) {
	return "", "", time.Time{}, oidc.ErrUnsupportedGrantType()
}
func (*storage) TokenRequestByRefreshToken(context.Context, string) (op.RefreshTokenRequest, error) {
	return nil, op.ErrInvalidRefreshToken
}
func (*storage) GetRefreshTokenInfo(context.Context, string, string) (string, string, error) {
	return "", "", op.ErrInvalidRefreshToken
}
func (*storage) TerminateSession(context.Context, string, string) error {
	return errors.New("logout is unsupported")
}
func (*storage) RevokeToken(context.Context, string, string, string) *oidc.Error {
	return oidc.ErrRequestNotSupported()
}
func (*storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}
func (*storage) SetIntrospectionFromToken(context.Context, *oidc.IntrospectionResponse, string, string, string) error {
	return errors.New("introspection is unsupported")
}
func (*storage) GetPrivateClaimsFromScopes(context.Context, string, string, []string) (map[string]any, error) {
	return nil, nil
}
func (*storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("client keys are unsupported")
}
func (*storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, oidc.ErrUnsupportedGrantType()
}

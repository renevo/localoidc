package main

import (
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type client struct {
	id       string
	redirect string
	method   oidc.AuthMethod
	cfg      settings
}

func (c client) GetID() string                       { return c.id }
func (c client) RedirectURIs() []string              { return []string{c.redirect} }
func (c client) PostLogoutRedirectURIs() []string    { return nil }
func (c client) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c client) AuthMethod() oidc.AuthMethod         { return c.method }
func (c client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c client) GrantTypes() []oidc.GrantType         { return []oidc.GrantType{oidc.GrantTypeCode} }
func (c client) LoginURL(id string) string            { return "/login?id=" + id }
func (c client) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeBearer }
func (c client) IDTokenLifetime() time.Duration       { return c.cfg.TokenLifetime }
func (c client) DevMode() bool                        { return true }
func (c client) ClockSkew() time.Duration             { return 0 }
func (c client) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c client) IsScopeAllowed(scope string) bool {
	_, ok := c.cfg.Scopes[scope]
	return ok
}
func (c client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

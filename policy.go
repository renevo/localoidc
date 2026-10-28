package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func localCallback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	// Exact literals only. Never resolve a supplied hostname or accept lookalikes.
	if !slices.Contains([]string{"localhost", "127.0.0.1", "::1"}, u.Hostname()) {
		return false
	}
	// Brackets are valid only for the IPv6 literal, not a way to spell a
	// hostname or IPv4 address. Reconstruct the authority to reject those forms.
	expectedHost := u.Hostname()
	if expectedHost == "::1" {
		expectedHost = "[::1]"
	}
	if u.Port() != "" {
		expectedHost += ":" + u.Port()
	}
	if u.Host != expectedHost {
		return false
	}
	if strings.Contains(u.Host, "%") || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return false
		}
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return false
	}
	return true
}

func (s settings) callbackAllowed(raw string) bool {
	return localCallback(raw) && (len(s.RedirectURIs) == 0 || slices.Contains(s.RedirectURIs, raw))
}

func (s settings) authorityAllowed(authority string) bool {
	host, port, err := net.SplitHostPort(authority)
	return err == nil && host == "127.0.0.1" && port == strconv.Itoa(s.Port)
}

func needsConfirmation(skip bool, prompts []string) (bool, error) {
	if slices.Contains(prompts, "none") && len(prompts) != 1 {
		return false, oidc.ErrInvalidRequest().WithDescription("prompt none cannot be combined with another prompt")
	}
	confirm := !skip
	for _, prompt := range prompts {
		switch prompt {
		case "none":
		case "login", "consent", "select_account":
			confirm = true
		default:
			return false, oidc.ErrInvalidRequest().WithDescription("unsupported prompt")
		}
	}
	if confirm && slices.Contains(prompts, "none") {
		return false, oidc.ErrInteractionRequired().WithDescription("local login confirmation is required")
	}
	return confirm, nil
}

func validateStandardClaims(claims map[string]any) error {
	data, err := json.Marshal(claims)
	if err != nil {
		return errors.New("identity claims must be valid JSON")
	}
	var info oidc.UserInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return errors.New("invalid standard identity claim type")
	}
	for _, name := range []string{"email_verified", "phone_number_verified"} {
		if value, exists := claims[name]; exists {
			if _, ok := value.(bool); !ok {
				return errors.New("verification claims must be JSON booleans")
			}
		}
	}
	return nil
}

func (s settings) claimsFor(scopes []string) map[string]any {
	claims := map[string]any{"sub": s.Identity.Subject}
	for _, scope := range scopes {
		for _, name := range s.Scopes[scope] {
			claims[name] = s.Identity.Claims[name]
		}
	}
	return claims
}

func (s settings) fillUserinfo(info *oidc.UserInfo, scopes []string) {
	info.Subject = s.Identity.Subject
	// AppendClaims preserves false, zero, and empty configured values that the
	// library's typed standard fields would otherwise omit during JSON encoding.
	for name, value := range s.claimsFor(scopes) {
		if name != "sub" {
			info.AppendClaims(name, value)
		}
	}
}

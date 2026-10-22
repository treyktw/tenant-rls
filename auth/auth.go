// Package auth verifies session tokens.
//
// A request is authenticated by a JWT in the Authorization header
// ("Bearer <token>"), signed by the identity provider's key. Nothing else is
// accepted: no cookie, no query parameter, no caller-supplied user or tenant.
// The verified subject is the only identity the rest of the API sees, and
// package db turns it into a tenant inside the request's own transaction.
//
// The provider is pluggable: anything that implements TokenVerifier works.
// JWTVerifier covers HS256 (shared secret, tests and demos) and ES256/RS256
// with a fixed key or a KeySource, which is how you plug in an OIDC provider's
// JWKS (Clerk, Auth0, Cognito, Keycloak, ...).
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/treyktw/tenant-rls/httpapi"
)

// Session is a verified session.
type Session struct {
	// Subject is the provider's stable user id (the JWT `sub`).
	Subject   string
	SessionID string
}

// TokenVerifier checks a bearer token.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (Session, error)
}

// KeySource returns the verification key for a token's kid: a
// *ecdsa.PublicKey, *rsa.PublicKey, []byte (HS256) or *jose.JSONWebKey. A
// JWKS-backed KeySource is how a real OIDC provider plugs in.
type KeySource func(ctx context.Context, kid string) (any, error)

// JWTVerifier verifies compact JWS tokens.
type JWTVerifier struct {
	keys              KeySource
	algorithms        []jose.SignatureAlgorithm
	issuer            string
	audience          string
	authorizedParties []string
	requireSessionID  bool
	subjectPrefix     string
	leeway            time.Duration
	now               func() time.Time
}

// Options configures NewJWTVerifier.
type Options struct {
	// HS256Secret verifies HS256 tokens with a shared secret (tests, demos).
	HS256Secret []byte
	// PublicKey verifies ES256 (*ecdsa.PublicKey) or RS256 (*rsa.PublicKey)
	// tokens with one fixed key.
	PublicKey any
	// Keys resolves keys by kid (JWKS). Takes precedence over the above.
	Keys KeySource
	// Algorithms restricts accepted algorithms. Defaults to the one the
	// configured key implies; required with Keys.
	Algorithms []jose.SignatureAlgorithm
	// Issuer, when set, must equal the iss claim.
	Issuer string
	// Audience, when set, must be in the aud claim.
	Audience string
	// AuthorizedParties restricts the azp claim when non-empty.
	AuthorizedParties []string
	// RequireSessionID rejects tokens without a sid claim (session tokens
	// always carry one; template or machine tokens do not).
	RequireSessionID bool
	// SubjectPrefix, when set, must prefix the subject (e.g. "user_").
	SubjectPrefix string
	// Now overrides the clock (tests).
	Now func() time.Time
}

// NewJWTVerifier builds a verifier from Options.
func NewJWTVerifier(opts Options) (*JWTVerifier, error) {
	v := &JWTVerifier{
		keys:              opts.Keys,
		algorithms:        opts.Algorithms,
		issuer:            opts.Issuer,
		audience:          opts.Audience,
		authorizedParties: opts.AuthorizedParties,
		requireSessionID:  opts.RequireSessionID,
		subjectPrefix:     opts.SubjectPrefix,
		leeway:            5 * time.Second,
		now:               opts.Now,
	}
	switch {
	case v.keys != nil:
		if len(v.algorithms) == 0 {
			return nil, errors.New("a KeySource needs an explicit algorithm list")
		}
	case len(opts.HS256Secret) > 0:
		if len(opts.HS256Secret) < 32 {
			return nil, errors.New("an HS256 secret must be at least 32 bytes")
		}
		v.keys = fixedKey(opts.HS256Secret)
		if len(v.algorithms) == 0 {
			v.algorithms = []jose.SignatureAlgorithm{jose.HS256}
		}
	case opts.PublicKey != nil:
		v.keys = fixedKey(opts.PublicKey)
		if len(v.algorithms) == 0 {
			alg, err := algorithmFor(opts.PublicKey)
			if err != nil {
				return nil, err
			}
			v.algorithms = []jose.SignatureAlgorithm{alg}
		}
	default:
		return nil, errors.New("an HS256 secret, a public key or a key source is required")
	}
	if v.now == nil {
		v.now = time.Now
	}
	return v, nil
}

type claims struct {
	jwt.Claims
	SessionID string `json:"sid,omitempty"`
	AZP       string `json:"azp,omitempty"`
}

// Verify checks the signature, algorithm, expiry, issuer, audience and
// authorized party.
func (v *JWTVerifier) Verify(ctx context.Context, token string) (Session, error) {
	// ParseSigned rejects any algorithm not in the list, "none" included.
	parsed, err := jwt.ParseSigned(token, v.algorithms)
	if err != nil {
		if strings.Contains(err.Error(), "unexpected signature algorithm") {
			return Session{}, fmt.Errorf("algorithm: %w", err)
		}
		return Session{}, errors.New("malformed token")
	}
	if len(parsed.Headers) != 1 {
		return Session{}, errors.New("malformed token")
	}
	key, err := v.keys(ctx, parsed.Headers[0].KeyID)
	if err != nil {
		return Session{}, fmt.Errorf("signing key: %w", err)
	}
	var c claims
	if err := parsed.Claims(key, &c); err != nil {
		return Session{}, fmt.Errorf("signing key: %w", err)
	}
	expected := jwt.Expected{Issuer: v.issuer, Time: v.now()}
	if v.audience != "" {
		expected.AnyAudience = jwt.Audience{v.audience}
	}
	if err := c.Claims.ValidateWithLeeway(expected, v.leeway); err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpired):
			return Session{}, errors.New("token expired")
		case errors.Is(err, jwt.ErrNotValidYet), errors.Is(err, jwt.ErrIssuedInTheFuture):
			return Session{}, errors.New("token not valid yet")
		case errors.Is(err, jwt.ErrInvalidIssuer):
			return Session{}, errors.New("invalid issuer")
		case errors.Is(err, jwt.ErrInvalidAudience):
			return Session{}, errors.New("invalid audience")
		default:
			return Session{}, err
		}
	}
	if c.Expiry == nil {
		return Session{}, errors.New("token has no expiry")
	}
	if len(v.authorizedParties) > 0 && !slices.Contains(v.authorizedParties, c.AZP) {
		return Session{}, errors.New("invalid authorized party")
	}
	if c.Subject == "" || !strings.HasPrefix(c.Subject, v.subjectPrefix) {
		return Session{}, errors.New("token has no user subject")
	}
	if v.requireSessionID && c.SessionID == "" {
		// Session tokens always carry sid; other provider JWTs (templates,
		// machine tokens) are not sessions and are not accepted here.
		return Session{}, errors.New("token is not a session token")
	}
	return Session{Subject: c.Subject, SessionID: c.SessionID}, nil
}

type ctxKey struct{}

// FromContext returns the verified session for this request.
func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(Session)
	return s, ok
}

// WithSession stores s in ctx (tests and the middleware).
func WithSession(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// Require rejects any request without a verified session.
func Require(v TokenVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r.Header.Get("Authorization"))
		if !ok {
			httpapi.WriteError(w, r, httpapi.ErrUnauthenticated)
			return
		}
		session, err := v.Verify(r.Context(), token)
		if err != nil {
			// The reason stays out of the response; the log gets a category.
			httpapi.Logger(r.Context()).Info("token rejected", "reason", rejectReason(err))
			httpapi.WriteError(w, r, httpapi.ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithSession(r.Context(), session)))
	})
}

func bearer(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func rejectReason(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "expired"):
		return "expired"
	case strings.Contains(msg, "not valid yet"), strings.Contains(msg, "issued in the future"):
		return "not_yet_valid"
	case strings.Contains(msg, "authorized party"):
		return "authorized_party"
	case strings.Contains(msg, "issuer"):
		return "issuer"
	case strings.Contains(msg, "audience"):
		return "audience"
	case strings.Contains(msg, "signing key"), strings.Contains(msg, "algorithm"):
		return "key"
	case strings.Contains(msg, "malformed"):
		return "malformed"
	default:
		return "invalid"
	}
}

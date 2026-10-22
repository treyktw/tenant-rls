package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	issuer   = "https://issuer.example.test"
	audience = "rls-kit-test"
)

type keyPair struct {
	priv *ecdsa.PrivateKey
	kid  string
}

func newKey(t *testing.T, kid string) keyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{priv: priv, kid: kid}
}

func sign(t *testing.T, key any, kid string, c TokenClaims) string {
	t.Helper()
	token, err := Sign(key, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func validClaims(now time.Time) TokenClaims {
	return TokenClaims{
		Subject:   "user_abc",
		SessionID: "sess_123",
		Issuer:    issuer,
		Audience:  audience,
		AZP:       "http://localhost:3000",
		IssuedAt:  now.Add(-10 * time.Second),
		TTL:       60 * time.Second,
	}
}

// verifierFor resolves keys by kid, the way a JWKS-backed KeySource does.
func verifierFor(t *testing.T, now time.Time, parties []string, keys ...keyPair) *JWTVerifier {
	t.Helper()
	byID := map[string]*ecdsa.PublicKey{}
	for _, k := range keys {
		byID[k.kid] = &k.priv.PublicKey
	}
	v, err := NewJWTVerifier(Options{
		Algorithms:        []jose.SignatureAlgorithm{jose.ES256},
		Issuer:            issuer,
		Audience:          audience,
		AuthorizedParties: parties,
		RequireSessionID:  true,
		SubjectPrefix:     "user_",
		Now:               func() time.Time { return now },
		Keys: func(_ context.Context, kid string) (any, error) {
			if k, ok := byID[kid]; ok {
				return k, nil
			}
			return nil, errors.New("unknown signing key")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyAcceptsAValidSessionToken(t *testing.T) {
	now := time.Now()
	k := newKey(t, "key_1")
	s, err := verifierFor(t, now, []string{"http://localhost:3000"}, k).Verify(context.Background(), sign(t, k.priv, k.kid, validClaims(now)))
	if err != nil {
		t.Fatal(err)
	}
	if s.Subject != "user_abc" || s.SessionID != "sess_123" {
		t.Fatalf("session = %+v", s)
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Now()
	k := newKey(t, "key_1")
	other := newKey(t, "key_1") // same kid, different key: a forged signature
	hsSecret := []byte("hs256-test-secret-FAKEFAKEFAKEFAKEFAKE")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() (string, *JWTVerifier){
		"expired": func() (string, *JWTVerifier) {
			c := validClaims(now)
			c.IssuedAt = now.Add(-2 * time.Minute)
			c.TTL = time.Minute
			return sign(t, k.priv, k.kid, c), verifierFor(t, now, nil, k)
		},
		"not yet valid": func() (string, *JWTVerifier) {
			c := validClaims(now)
			c.IssuedAt = now.Add(time.Minute)
			return sign(t, k.priv, k.kid, c), verifierFor(t, now, nil, k)
		},
		"forged signature": func() (string, *JWTVerifier) {
			return sign(t, other.priv, other.kid, validClaims(now)), verifierFor(t, now, nil, k)
		},
		"unknown kid": func() (string, *JWTVerifier) {
			k2 := newKey(t, "key_2")
			return sign(t, k2.priv, k2.kid, validClaims(now)), verifierFor(t, now, nil, k)
		},
		"foreign issuer": func() (string, *JWTVerifier) {
			c := validClaims(now)
			c.Issuer = "https://evil.example"
			return sign(t, k.priv, k.kid, c), verifierFor(t, now, nil, k)
		},
		"foreign audience": func() (string, *JWTVerifier) {
			c := validClaims(now)
			c.Audience = "some-other-api"
			return sign(t, k.priv, k.kid, c), verifierFor(t, now, nil, k)
		},
		"authorized party": func() (string, *JWTVerifier) {
			c := validClaims(now)
			c.AZP = "https://evil.example"
			return sign(t, k.priv, k.kid, c), verifierFor(t, now, []string{"http://localhost:3000"}, k)
		},
		"not a session token": func() (string, *JWTVerifier) {
			c := validClaims(now)
			c.SessionID = ""
			return sign(t, k.priv, k.kid, c), verifierFor(t, now, nil, k)
		},
		"not a user": func() (string, *JWTVerifier) {
			c := validClaims(now)
			c.Subject = "org_123"
			return sign(t, k.priv, k.kid, c), verifierFor(t, now, nil, k)
		},
		"garbage": func() (string, *JWTVerifier) {
			return "not-a-jwt", verifierFor(t, now, nil, k)
		},
		"alg none": func() (string, *JWTVerifier) {
			// An unsigned token: header {"alg":"none","kid":"key_1"}, a payload
			// with a valid subject, and an empty signature.
			enc := base64.RawURLEncoding.EncodeToString
			return enc([]byte(`{"alg":"none","kid":"key_1"}`)) + "." +
				enc([]byte(`{"sub":"user_abc","sid":"sess_123"}`)) + ".", verifierFor(t, now, nil, k)
		},
		"HS256 where ES256 is expected": func() (string, *JWTVerifier) {
			// The classic confusion attack: an HMAC token keyed with
			// something the attacker knows. The algorithm list stops it
			// before any key is consulted.
			return sign(t, hsSecret, k.kid, validClaims(now)), verifierFor(t, now, nil, k)
		},
		"RS256 where ES256 is expected": func() (string, *JWTVerifier) {
			return sign(t, rsaKey, k.kid, validClaims(now)), verifierFor(t, now, nil, k)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			token, v := build()
			if _, err := v.Verify(context.Background(), token); err == nil {
				t.Fatal("token was accepted")
			}
		})
	}
}

func TestHS256AndFixedKeyVerifiers(t *testing.T) {
	now := time.Now()
	secret := []byte("hs256-test-secret-FAKEFAKEFAKEFAKEFAKE")
	hs, err := NewJWTVerifier(Options{HS256Secret: secret, Issuer: issuer, Audience: audience, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := hs.Verify(context.Background(), sign(t, secret, "", validClaims(now))); err != nil || s.Subject != "user_abc" {
		t.Fatalf("HS256: %+v %v", s, err)
	}
	if _, err := hs.Verify(context.Background(), sign(t, []byte("a-different-secret-FAKEFAKEFAKEFAKE"), "", validClaims(now))); err == nil {
		t.Fatal("HS256 accepted a token signed with another secret")
	}

	k := newKey(t, "")
	es, err := NewJWTVerifier(Options{PublicKey: &k.priv.PublicKey, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.Verify(context.Background(), sign(t, k.priv, "", validClaims(now))); err != nil {
		t.Fatalf("ES256 fixed key: %v", err)
	}
	// A fixed ES256 key never accepts an HS256 token, whatever its secret.
	if _, err := es.Verify(context.Background(), sign(t, secret, "", validClaims(now))); err == nil {
		t.Fatal("ES256 verifier accepted HS256")
	}
}

func TestRequire(t *testing.T) {
	now := time.Now()
	k := newKey(t, "key_1")
	v := verifierFor(t, now, nil, k)
	var seen Session
	h := Require(v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	forger := newKey(t, "key_1")
	for name, header := range map[string]string{
		"missing":   "",
		"basic":     "Basic dXNlcjpwYXNz",
		"empty":     "Bearer ",
		"forged":    "Bearer " + sign(t, forger.priv, forger.kid, validClaims(now)),
		"malformed": "Bearer abc.def",
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d", rec.Code)
			}
		})
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+sign(t, k.priv, k.kid, validClaims(now)))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || seen.Subject != "user_abc" {
		t.Fatalf("status = %d, session = %+v", rec.Code, seen)
	}
}

func TestNewJWTVerifierNeedsAKey(t *testing.T) {
	if _, err := NewJWTVerifier(Options{}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := NewJWTVerifier(Options{HS256Secret: []byte("short")}); err == nil {
		t.Fatal("expected a short-secret error")
	}
	if _, err := NewJWTVerifier(Options{Keys: func(context.Context, string) (any, error) { return nil, nil }}); err == nil {
		t.Fatal("expected a missing-algorithm error")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewJWTVerifier(Options{PublicKey: &k.PublicKey}); err == nil {
		t.Fatal("expected an unsupported-curve error")
	}
}

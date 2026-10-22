package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fixedKey is a KeySource that ignores kid.
func fixedKey(key any) KeySource {
	return func(context.Context, string) (any, error) { return key, nil }
}

func algorithmFor(key any) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", errors.New("only P-256 ECDSA keys (ES256) are supported")
		}
		return jose.ES256, nil
	case *rsa.PublicKey:
		return jose.RS256, nil
	default:
		return "", errors.New("unsupported public key type")
	}
}

// TokenClaims are what Sign puts in a token.
type TokenClaims struct {
	Subject   string
	SessionID string
	Issuer    string
	Audience  string
	AZP       string
	IssuedAt  time.Time
	TTL       time.Duration
}

// Sign issues a compact JWS for tests, the demo and cmd/mint-token. key is a
// []byte (HS256), *ecdsa.PrivateKey (ES256) or *rsa.PrivateKey (RS256). A
// real deployment never signs: the identity provider does.
func Sign(key any, kid string, c TokenClaims) (string, error) {
	var alg jose.SignatureAlgorithm
	switch key.(type) {
	case []byte:
		alg = jose.HS256
	case *ecdsa.PrivateKey:
		alg = jose.ES256
	case *rsa.PrivateKey:
		alg = jose.RS256
	default:
		return "", errors.New("unsupported signing key type")
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return "", err
	}
	issued := c.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}
	ttl := c.TTL
	if ttl == 0 {
		ttl = time.Hour
	}
	body := claims{
		Claims: jwt.Claims{
			Issuer:    c.Issuer,
			Subject:   c.Subject,
			IssuedAt:  jwt.NewNumericDate(issued),
			NotBefore: jwt.NewNumericDate(issued),
			Expiry:    jwt.NewNumericDate(issued.Add(ttl)),
		},
		SessionID: c.SessionID,
		AZP:       c.AZP,
	}
	if c.Audience != "" {
		body.Audience = jwt.Audience{c.Audience}
	}
	return jwt.Signed(signer).Claims(body).Serialize()
}

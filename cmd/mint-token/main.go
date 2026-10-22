// Command mint-token prints a demo HS256 session token for a subject, signed
// with AUTH_HS256_SECRET. It stands in for the identity provider; a real
// deployment never mints tokens itself.
//
//	go run ./cmd/mint-token user_acme_admin
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/treyktw/tenant-rls/auth"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: mint-token <subject>")
		os.Exit(2)
	}
	secret := os.Getenv("AUTH_HS256_SECRET")
	if len(secret) < 32 {
		fmt.Fprintln(os.Stderr, "mint-token: AUTH_HS256_SECRET must be set (32+ bytes); see .env.example")
		os.Exit(1)
	}
	token, err := auth.Sign([]byte(secret), "", auth.TokenClaims{
		Subject:   os.Args[1],
		SessionID: "sess_demo",
		Issuer:    os.Getenv("AUTH_ISSUER"),
		Audience:  os.Getenv("AUTH_AUDIENCE"),
		TTL:       time.Hour,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint-token:", err)
		os.Exit(1)
	}
	fmt.Println(token)
}

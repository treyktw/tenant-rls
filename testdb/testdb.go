// Package testdb gives integration tests the two runtime logins and
// disposable fixtures.
//
// The tests run against a real database: the docker compose Postgres locally
// (make db-up) and the same in CI. Without APP_DATABASE_URL and
// PLATFORM_DATABASE_URL they skip, unless REQUIRE_DB=1, which CI sets so a
// missing database fails instead of passing silently.
//
// Fixtures go in through the platform login, the path real platform writes
// use, with ids and subjects unique to the test, and are deleted when the
// test ends. Their events reach the outbox like any other write.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/treyktw/tenant-rls/db"
)

// URLs returns the app and platform URLs, skipping the test if unset.
func URLs(t testing.TB) (app, platform string) {
	t.Helper()
	app = os.Getenv("APP_DATABASE_URL")
	platform = os.Getenv("PLATFORM_DATABASE_URL")
	if app == "" || platform == "" {
		if os.Getenv("REQUIRE_DB") == "1" {
			t.Fatal("REQUIRE_DB=1 but the database URLs are not set")
		}
		t.Skip("APP_DATABASE_URL / PLATFORM_DATABASE_URL not set; run `make db-up` and load .env.example")
	}
	return app, platform
}

// Env returns an extra connection URL from the environment, skipping the
// test if unset (relay, owner and the BYPASSRLS demo login).
func Env(t testing.TB, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		if os.Getenv("REQUIRE_DB") == "1" {
			t.Fatalf("REQUIRE_DB=1 but %s is not set", name)
		}
		t.Skipf("%s not set", name)
	}
	return v
}

// Open returns a *db.DB for the test, closed at cleanup.
func Open(t testing.TB) *db.DB {
	t.Helper()
	app, platform := URLs(t)
	d, err := db.Open(context.Background(), app, platform)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// Fixture is one disposable tenant with members.
type Fixture struct {
	TenantID string
	Admin    Member
	Manager  Member
	Member   Member
	// Unbound has a subject and no tenant (onboarding).
	Unbound Member
}

// Member is a fixture member.
type Member struct {
	MemberID string
	Subject  string
	Email    string
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newMember(tag string) Member {
	suffix := randomHex(6)
	return Member{
		MemberID: uuid(),
		Subject:  "user_kittest" + suffix,
		Email:    fmt.Sprintf("kit-test+%s-%s@example.test", tag, suffix),
	}
}

// UUID returns a random version 4 UUID for fixture rows.
func UUID() string { return uuid() }

func uuid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Platform runs fn as the platform login with app.platform on, committing.
func Platform(t testing.TB, fn func(tx pgx.Tx) error) {
	t.Helper()
	_, platformURL := URLs(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, platformURL)
	if err != nil {
		t.Fatalf("connect platform: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('app.platform', 'on', true)"); err != nil {
		t.Fatal(err)
	}
	if err := fn(tx); err != nil {
		t.Fatalf("platform fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// NewFixture creates a tenant with an ADMIN, a MANAGER, a MEMBER and one
// unbound member, all removed at cleanup.
func NewFixture(t testing.TB) Fixture {
	t.Helper()
	f := Fixture{
		TenantID: uuid(),
		Admin:    newMember("admin"),
		Manager:  newMember("manager"),
		Member:   newMember("member"),
		Unbound:  newMember("unbound"),
	}
	Platform(t, func(tx pgx.Tx) error {
		ctx := context.Background()
		if _, err := tx.Exec(ctx,
			"INSERT INTO app.tenants (id, name, slug) VALUES ($1, $2, $3)",
			f.TenantID, "Kit Test Tenant "+randomHex(3), "kit-test-"+randomHex(6)); err != nil {
			return err
		}
		for _, m := range []struct {
			m    Member
			role string
		}{{f.Admin, "ADMIN"}, {f.Manager, "MANAGER"}, {f.Member, "MEMBER"}} {
			if _, err := tx.Exec(ctx,
				`INSERT INTO app.members (id, tenant_id, subject, email, display_name, role)
				 VALUES ($1, $2, $3, $4, $5, $6)`,
				m.m.MemberID, f.TenantID, m.m.Subject, m.m.Email, "Test "+m.role, m.role); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO app.members (id, subject, email, display_name, needs_onboarding)
			 VALUES ($1, $2, $3, 'Test Unbound', true)`,
			f.Unbound.MemberID, f.Unbound.Subject, f.Unbound.Email)
		return err
	})
	t.Cleanup(func() {
		Platform(t, func(tx pgx.Tx) error {
			ctx := context.Background()
			// Rows that reference the members go first; notes cascade with
			// their projects.
			if _, err := tx.Exec(ctx, "DELETE FROM app.projects WHERE tenant_id = $1", f.TenantID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				"DELETE FROM app.members WHERE id = ANY($1)",
				[]string{f.Admin.MemberID, f.Manager.MemberID, f.Member.MemberID, f.Unbound.MemberID}); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "DELETE FROM app.tenants WHERE id = $1", f.TenantID)
			return err
		})
	})
	return f
}

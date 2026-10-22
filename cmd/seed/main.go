// Command seed creates the demo's two tenants through the platform path, the
// way an auth webhook or back office would. It is idempotent: rerunning it
// leaves the same rows.
//
//	PLATFORM_DATABASE_URL=... go run ./cmd/seed
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/treyktw/tenant-rls/db"
)

// Fixed ids so the README's curl examples work as written.
const (
	acmeTenant    = "11111111-1111-4111-8111-111111111111"
	acmeAdmin     = "11111111-1111-4111-8111-1111111111a1"
	acmeMember    = "11111111-1111-4111-8111-1111111111a2"
	acmeProject   = "11111111-1111-4111-8111-1111111111f1"
	globexTenant  = "22222222-2222-4222-8222-222222222222"
	globexAdmin   = "22222222-2222-4222-8222-2222222222b1"
	globexProject = "22222222-2222-4222-8222-2222222222f1"
	unboundMember = "33333333-3333-4333-8333-3333333333c1"
)

type statement struct {
	sql  string
	args []any
}

var seed = []statement{
	{`INSERT INTO app.tenants (id, name, slug) VALUES ($1, 'Acme Rockets', 'acme'), ($2, 'Globex Corporation', 'globex')
	  ON CONFLICT (id) DO NOTHING`, []any{acmeTenant, globexTenant}},
	{`INSERT INTO app.members (id, tenant_id, subject, email, display_name, role) VALUES
	    ($1, $4, 'user_acme_admin',   'ada@acme.example.test',   'Ada (Acme admin)',   'ADMIN'),
	    ($2, $4, 'user_acme_member',  'max@acme.example.test',   'Max (Acme member)',  'MEMBER'),
	    ($3, $5, 'user_globex_admin', 'gus@globex.example.test', 'Gus (Globex admin)', 'ADMIN')
	  ON CONFLICT (id) DO NOTHING`, []any{acmeAdmin, acmeMember, globexAdmin, acmeTenant, globexTenant}},
	{`INSERT INTO app.members (id, subject, email, display_name, needs_onboarding)
	  VALUES ($1, 'user_new_signup', 'new@example.test', 'New signup (no tenant yet)', true)
	  ON CONFLICT (id) DO NOTHING`, []any{unboundMember}},
	{`INSERT INTO app.projects (id, tenant_id, name, created_by) VALUES
	    ($1, $2, 'Acme launch plan', $3),
	    ($4, $5, 'Globex merger (confidential)', $6)
	  ON CONFLICT (id) DO NOTHING`, []any{acmeProject, acmeTenant, acmeAdmin, globexProject, globexTenant, globexAdmin}},
	{`INSERT INTO app.notes (id, tenant_id, project_id, author_id, body) VALUES
	    ('11111111-1111-4111-8111-1111111111e1', $1, $2, $3, 'Fuel order placed.'),
	    ('22222222-2222-4222-8222-2222222222e1', $4, $5, $6, 'Board meets Friday. Do not share.')
	  ON CONFLICT (id) DO NOTHING`, []any{acmeTenant, acmeProject, acmeMember, globexTenant, globexProject, globexAdmin}},
}

func main() {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("PLATFORM_DATABASE_URL"))
	if err != nil {
		fail(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	// Same check the server's platform pool runs on every connection.
	if err := db.VerifyPlatformLogin(ctx, conn); err != nil {
		fail(err)
	}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.platform', 'on', true)`); err != nil {
			return err
		}
		for _, s := range seed {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fail(err)
	}
	fmt.Println("seeded tenants acme and globex")
	fmt.Println("  subjects: user_acme_admin, user_acme_member, user_globex_admin, user_new_signup (no tenant)")
	fmt.Printf("  acme project:   %s\n  globex project: %s\n", acmeProject, globexProject)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "seed:", err)
	os.Exit(1)
}

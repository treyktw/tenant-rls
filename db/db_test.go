package db_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/treyktw/tenant-rls/db"
	"github.com/treyktw/tenant-rls/testdb"
)

func TestTenantBindsFromTheSubjectOnly(t *testing.T) {
	d := testdb.Open(t)
	f := testdb.NewFixture(t)
	other := testdb.NewFixture(t)
	ctx := context.Background()

	err := d.WithTenant(ctx, f.Member.Subject, db.TenantOptions{}, func(tx db.Tx, tenant db.Tenant) error {
		if tenant.MemberID != f.Member.MemberID || tenant.TenantID != f.TenantID || tenant.Role != "MEMBER" {
			t.Errorf("tenant = %+v", tenant)
		}
		var subject, member, tenantID string
		if err := tx.Raw.QueryRow(ctx, `SELECT current_setting('app.subject', true),
			current_setting('app.member_id', true), current_setting('app.tenant_id', true)`).
			Scan(&subject, &member, &tenantID); err != nil {
			return err
		}
		if subject != "" {
			t.Error("app.subject was not cleared before domain SQL")
		}
		if member != f.Member.MemberID || tenantID != f.TenantID {
			t.Errorf("settings = %q %q", member, tenantID)
		}
		// RLS, not a WHERE clause, keeps the other fixture out.
		var tenants, foreign int
		if err := tx.Raw.QueryRow(ctx, "SELECT count(*) FROM app.tenants").Scan(&tenants); err != nil {
			return err
		}
		if err := tx.Raw.QueryRow(ctx, "SELECT count(*) FROM app.members WHERE tenant_id = $1",
			other.TenantID).Scan(&foreign); err != nil {
			return err
		}
		if tenants != 1 || foreign != 0 {
			t.Errorf("saw %d tenants and %d foreign members", tenants, foreign)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTenantRefusesUnknownInactiveAndUnbound(t *testing.T) {
	d := testdb.Open(t)
	f := testdb.NewFixture(t)
	ctx := context.Background()
	never := func(db.Tx, db.Tenant) error {
		t.Error("work ran without a tenant")
		return nil
	}

	for name, subject := range map[string]string{
		"unknown": "user_kittest_nobody",
		"empty":   "",
		"unbound": f.Unbound.Subject,
	} {
		if err := d.WithTenant(ctx, subject, db.TenantOptions{}, never); !errors.Is(err, db.ErrNoTenant) {
			t.Errorf("%s: err = %v", name, err)
		}
	}

	testdb.Platform(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE app.members SET is_active = false WHERE id = $1", f.Manager.MemberID)
		return err
	})
	if err := d.WithTenant(ctx, f.Manager.Subject, db.TenantOptions{}, never); !errors.Is(err, db.ErrNoTenant) {
		t.Errorf("inactive: err = %v", err)
	}
}

func TestTenantSuspended(t *testing.T) {
	d := testdb.Open(t)
	f := testdb.NewFixture(t)
	ctx := context.Background()
	testdb.Platform(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE app.tenants SET suspended_at = now() WHERE id = $1", f.TenantID)
		return err
	})

	err := d.WithTenant(ctx, f.Admin.Subject, db.TenantOptions{}, func(db.Tx, db.Tenant) error {
		t.Error("domain work ran for a suspended tenant")
		return nil
	})
	if !errors.Is(err, db.ErrNoTenant) {
		t.Fatalf("err = %v", err)
	}
	ran := false
	err = d.WithTenant(ctx, f.Admin.Subject, db.TenantOptions{AllowSuspended: true}, func(db.Tx, db.Tenant) error {
		ran = true
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("identity read of a suspended tenant: ran=%v err=%v", ran, err)
	}
}

func TestTenantIsReadOnlyByDefault(t *testing.T) {
	d := testdb.Open(t)
	f := testdb.NewFixture(t)
	ctx := context.Background()
	err := d.WithTenant(ctx, f.Admin.Subject, db.TenantOptions{}, func(tx db.Tx, tenant db.Tenant) error {
		_, err := tx.Raw.Exec(ctx, "UPDATE app.tenants SET name = name WHERE id = $1", tenant.TenantID)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "25006" {
		t.Fatalf("expected read_only_sql_transaction, got %v", err)
	}
}

func TestTenantWriteRollsBackOnError(t *testing.T) {
	d := testdb.Open(t)
	f := testdb.NewFixture(t)
	ctx := context.Background()
	boom := errors.New("boom")
	err := d.WithTenant(ctx, f.Admin.Subject, db.TenantOptions{Write: true}, func(tx db.Tx, tenant db.Tenant) error {
		if _, err := tx.Raw.Exec(ctx, "UPDATE app.tenants SET name = 'rolled back' WHERE id = $1",
			tenant.TenantID); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	var name string
	_ = d.WithTenant(ctx, f.Admin.Subject, db.TenantOptions{}, func(tx db.Tx, tenant db.Tenant) error {
		return tx.Raw.QueryRow(ctx, "SELECT name FROM app.tenants").Scan(&name)
	})
	if name == "rolled back" || name == "" {
		t.Fatalf("a failed unit of work committed (name = %q)", name)
	}
}

func TestReadOwnMemberSeesOnlyItself(t *testing.T) {
	d := testdb.Open(t)
	f := testdb.NewFixture(t)
	row, err := d.ReadOwnMember(context.Background(), f.Unbound.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if row.ID != f.Unbound.MemberID || row.TenantID != nil || !row.NeedsOnboarding {
		t.Fatalf("row = %+v", row)
	}
	if _, err := d.ReadOwnMember(context.Background(), "user_kittest_nobody"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unknown subject: %v", err)
	}
}

func TestPlatformSetsTheFlag(t *testing.T) {
	d := testdb.Open(t)
	var flag string
	err := d.WithPlatform(context.Background(), func(tx db.Tx) error {
		return tx.Raw.QueryRow(context.Background(), "SELECT current_setting('app.platform', true)").Scan(&flag)
	})
	if err != nil || flag != "on" {
		t.Fatalf("flag = %q, err = %v", flag, err)
	}
}

func TestOpenRefusesTheWrongLogins(t *testing.T) {
	app, platform := testdb.URLs(t)
	ctx := context.Background()

	// Each login is refused in the other's place: the database, not the URL,
	// decides.
	if _, err := db.Open(ctx, platform, platform); !errors.Is(err, db.ErrWrongRole) {
		t.Errorf("platform login as app: %v", err)
	}
	if _, err := db.Open(ctx, app, app); !errors.Is(err, db.ErrWrongRole) {
		t.Errorf("app login as platform: %v", err)
	}

	u, err := url.Parse(app)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("rls_owner", "not-a-real-password")
	if _, err := db.Open(ctx, u.String(), platform, db.Options{ForbiddenLogins: []string{"rls_owner"}}); err == nil {
		t.Error("owner URL accepted")
	}
}

// The database decides, not the URL: the real owner login (CREATEROLE, owns
// the tables, implicit admin member of every group role it created) and a
// BYPASSRLS login that is a plain app_user member are both refused, with no
// name list configured.
func TestOpenRefusesOwnerAndBypassRLS(t *testing.T) {
	_, platform := testdb.URLs(t)
	ctx := context.Background()
	for name, url := range map[string]string{
		"owner":     testdb.Env(t, "OWNER_DATABASE_URL"),
		"bypassrls": testdb.Env(t, "BYPASS_DATABASE_URL"),
		"relay":     testdb.Env(t, "RELAY_DATABASE_URL"),
	} {
		if _, err := db.Open(ctx, url, platform); !errors.Is(err, db.ErrWrongRole) {
			t.Errorf("%s login as app: %v", name, err)
		}
	}
}

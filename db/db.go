// Package db runs every request against Postgres under the request contract
// in the README. Any other service that talks to the same database must stay
// exactly as strict.
//
// TRUST BOUNDARY
// The database trusts app.tenant_id, app.member_id and app.subject and
// cannot verify them. This package is the only place the API sets them, and
// only from a subject package auth has verified. The runtime logins never
// leave the server.
//
// RESOLVING THE TENANT
// A request knows only its verified subject. Each tenant transaction sets
// app.subject, which lets app_user read the single app.members row bound to
// that subject (0005), takes the member and tenant from it, binds those, and
// clears app.subject again before any domain SQL runs. No row, an inactive
// member, or a suspended or deleted tenant means no tenant, and the work
// never runs.
//
// LOGINS
// Tenant work runs as an app_user member; platform work (the auth path and
// the verifiers) as a platform_admin member with app.platform = 'on'. Every
// new connection asks the database whether its login is exactly that and
// cannot bypass RLS, and is discarded if not, so the owner or a superuser can
// never serve a request even if a URL points at one.
package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/treyktw/tenant-rls/store"
)

// ErrNoTenant means the subject has no active account in an active tenant.
// Handlers answer it as 403 no_tenant.
var ErrNoTenant = errors.New("no active account is bound to this session")

// ErrWrongRole means a login is not the role it is configured as.
var ErrWrongRole = errors.New("database login is not a plain member of its runtime role, or can bypass RLS")

// Tenant is the caller as Postgres knows them.
type Tenant struct {
	MemberID string
	TenantID string
	Role     string
}

// Tx is the handle a unit of work receives.
type Tx struct {
	*store.Queries
	// Raw is the underlying transaction, for SQL sqlc cannot express.
	Raw pgx.Tx
}

// DB holds the two runtime pools.
type DB struct {
	app      *pgxpool.Pool
	platform *pgxpool.Pool
}

type role string

const (
	roleApp      role = "app_user"
	rolePlatform role = "platform_admin"
	roleRelay    role = "outbox_relay"
)

// verifyLoginSQL accepts a login only if it is a member of $1 and of neither
// other runtime group, and is neither superuser nor BYPASSRLS, cannot create
// roles, and owns nothing in schema app. The group names are fixed:
// app_user, platform_admin, outbox_relay.
//
// The CREATEROLE and ownership checks matter for the schema owner: in
// Postgres 16 the role that created the group roles is an implicit (admin)
// member of each, so it would otherwise pass the membership test, and as
// table owner it could ALTER TABLE ... NO FORCE ROW LEVEL SECURITY.
const verifyLoginSQL = `
SELECT pg_has_role(current_user, $1::text, 'MEMBER')
   AND (SELECT count(*) FROM unnest(ARRAY['app_user', 'platform_admin', 'outbox_relay']) g
        WHERE g <> $1::text AND pg_has_role(current_user, g, 'MEMBER')) = 0
   AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole
   AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = 'app' AND c.relowner = r.oid)
   AND NOT EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = 'app' AND n.nspowner = r.oid)
FROM pg_roles r WHERE r.rolname = current_user`

func verifyLogin(ctx context.Context, conn *pgx.Conn, want role) error {
	var ok bool
	if err := conn.QueryRow(ctx, verifyLoginSQL, string(want)).Scan(&ok); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrWrongRole
		}
		return fmt.Errorf("verify %s login: %w", want, err)
	}
	if !ok {
		return fmt.Errorf("%w (expected %s)", ErrWrongRole, want)
	}
	return nil
}

// Options tunes Open.
type Options struct {
	// ForbiddenLogins are login names refused before connecting: your
	// provider's owner role, for example. The database check catches every
	// unsafe login anyway; this just fails faster and says why.
	ForbiddenLogins []string
	// AppMaxConns and PlatformMaxConns size the pools (default 10 and 4).
	AppMaxConns      int32
	PlatformMaxConns int32
}

func newPool(ctx context.Context, name, raw string, want role, maxConns int32, forbidden []string) (*pgxpool.Pool, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		// Never echo the value: it carries the password.
		return nil, fmt.Errorf("%s is not a valid connection URL", name)
	}
	for _, f := range forbidden {
		if strings.EqualFold(u.User.Username(), f) {
			return nil, fmt.Errorf("%s uses the owner role", name)
		}
	}
	cfg, err := pgxpool.ParseConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid connection URL", name)
	}
	cfg.MaxConns = maxConns
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		return verifyLogin(ctx, conn, want)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return pool, nil
}

// Open connects both pools and checks each login once before returning.
func Open(ctx context.Context, appURL, platformURL string, opts ...Options) (*DB, error) {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if o.AppMaxConns == 0 {
		o.AppMaxConns = 10
	}
	if o.PlatformMaxConns == 0 {
		o.PlatformMaxConns = 4
	}
	app, err := newPool(ctx, "APP_DATABASE_URL", appURL, roleApp, o.AppMaxConns, o.ForbiddenLogins)
	if err != nil {
		return nil, err
	}
	platform, err := newPool(ctx, "PLATFORM_DATABASE_URL", platformURL, rolePlatform, o.PlatformMaxConns, o.ForbiddenLogins)
	if err != nil {
		app.Close()
		return nil, err
	}
	d := &DB{app: app, platform: platform}
	if err := d.Ping(ctx); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// Ping acquires a connection from each pool, which runs the login check on
// any new connection.
func (d *DB) Ping(ctx context.Context) error {
	if err := d.app.Ping(ctx); err != nil {
		return fmt.Errorf("app database: %w", err)
	}
	if err := d.platform.Ping(ctx); err != nil {
		return fmt.Errorf("platform database: %w", err)
	}
	return nil
}

// Close closes both pools.
func (d *DB) Close() {
	d.app.Close()
	d.platform.Close()
}

// TenantOptions tunes WithTenant.
type TenantOptions struct {
	// Write opens a read-write transaction. What the caller can then write is
	// decided by app_user's grants and gates, not here.
	Write bool
	// AllowSuspended binds a suspended or deleted tenant anyway. Only for
	// reading the tenant's own identity, so screens can explain a
	// suspension; never for domain work.
	AllowSuspended bool
}

// WithTenant runs fn in one transaction scoped to the subject's tenant.
func (d *DB) WithTenant(ctx context.Context, subject string, opts TenantOptions, fn func(tx Tx, t Tenant) error) error {
	if subject == "" {
		return ErrNoTenant
	}
	txOpts := pgx.TxOptions{AccessMode: pgx.ReadOnly}
	if opts.Write {
		txOpts.AccessMode = pgx.ReadWrite
	}
	return d.run(ctx, d.app, txOpts, func(tx Tx) error {
		if err := tx.SetSubject(ctx, subject); err != nil {
			return err
		}
		row, err := tx.ResolveTenant(ctx, subject)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoTenant
		}
		if err != nil {
			return err
		}
		if row.TenantID == nil {
			return ErrNoTenant
		}
		tenant := Tenant{
			MemberID: row.ID,
			TenantID: *row.TenantID,
			Role:     row.Role,
		}
		if err := tx.BindTenant(ctx, store.BindTenantParams{
			MemberID: tenant.MemberID,
			TenantID: tenant.TenantID,
		}); err != nil {
			return err
		}
		if !opts.AllowSuspended {
			n, err := tx.CountActiveTenants(ctx)
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrNoTenant
			}
		}
		return fn(tx, tenant)
	})
}

// ReadOwnMember returns the subject's own member row, whether or not they
// belong to a tenant yet (onboarding, account pending). It uses the 0005
// binding read: with only app.subject set, app_user sees that row and
// nothing else. pgx.ErrNoRows means there is no row.
func (d *DB) ReadOwnMember(ctx context.Context, subject string) (store.Member, error) {
	var row store.Member
	if subject == "" {
		return row, pgx.ErrNoRows
	}
	err := d.run(ctx, d.app, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx Tx) error {
		if err := tx.SetSubject(ctx, subject); err != nil {
			return err
		}
		var err error
		row, err = tx.GetOwnMember(ctx, subject)
		return err
	})
	return row, err
}

// WithPlatform runs fn in one platform transaction (platform_admin with
// app.platform = 'on'). Callers key every statement on a verified subject or
// on ids a tenant transaction resolved, never on caller input alone.
func (d *DB) WithPlatform(ctx context.Context, fn func(tx Tx) error) error {
	return d.run(ctx, d.platform, pgx.TxOptions{}, func(tx Tx) error {
		if err := tx.EnablePlatform(ctx); err != nil {
			return err
		}
		return fn(tx)
	})
}

func (d *DB) run(ctx context.Context, pool *pgxpool.Pool, opts pgx.TxOptions, fn func(tx Tx) error) error {
	tx, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	// Rollback after Commit is a no-op.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(Tx{Queries: store.New(tx), Raw: tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IsInsufficientPrivilege reports whether err is Postgres refusing a write
// (SQLSTATE 42501): a missing grant or a failed RLS check.
func IsInsufficientPrivilege(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}

// IsUniqueViolation reports whether err is SQLSTATE 23505.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsForeignKeyViolation reports whether err is SQLSTATE 23503: with
// composite (tenant_id, id) keys, a reference to another tenant's row fails
// exactly like a reference to a row that does not exist.
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// VerifyRelayLogin checks a connection is a plain outbox_relay member, for
// a relay process that drains the outbox on its own pool.
func VerifyRelayLogin(ctx context.Context, conn *pgx.Conn) error {
	return verifyLogin(ctx, conn, roleRelay)
}

// VerifyPlatformLogin checks a connection is a plain platform_admin member,
// for tools (seeders, backfills) that open their own platform connection.
func VerifyPlatformLogin(ctx context.Context, conn *pgx.Conn) error {
	return verifyLogin(ctx, conn, rolePlatform)
}

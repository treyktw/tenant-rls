// Package store holds the SQL the kit runs, as small hand-written query
// methods over pgx. It plays the part sqlc-generated code plays in a larger
// service: one method per statement, no ORM, and nothing here decides which
// tenant a statement runs for. That is internal to package db, which binds
// the tenant before any of these run; RLS does the filtering.
package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX is what Queries runs against: a pgx.Tx inside package db.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Queries wraps a DBTX.
type Queries struct {
	db DBTX
}

// New returns Queries over db.
func New(db DBTX) *Queries { return &Queries{db: db} }

// ---------------------------------------------------------------------------
// The request contract (README, "Request contract"). These run in this order
// at the start of every tenant transaction; package db is the only caller.
// ---------------------------------------------------------------------------

const setSubject = `SELECT set_config('app.subject', $1::text, true)`

// SetSubject sets app.subject, which (0005) makes the subject's own member
// row, and nothing else, visible.
func (q *Queries) SetSubject(ctx context.Context, subject string) error {
	_, err := q.db.Exec(ctx, setSubject, subject)
	return err
}

const resolveTenant = `
SELECT id, tenant_id, role
FROM app.members
WHERE subject = $1::text AND is_active AND tenant_id IS NOT NULL`

// ResolveTenantRow is the subject's binding.
type ResolveTenantRow struct {
	ID       string
	TenantID *string
	Role     string
}

// ResolveTenant is visible only through the 0005 binding read while
// app.subject is set.
func (q *Queries) ResolveTenant(ctx context.Context, subject string) (ResolveTenantRow, error) {
	var r ResolveTenantRow
	err := q.db.QueryRow(ctx, resolveTenant, subject).Scan(&r.ID, &r.TenantID, &r.Role)
	return r, err
}

const bindTenant = `
SELECT set_config('app.member_id', $1::text, true),
       set_config('app.tenant_id', $2::text, true),
       set_config('app.subject', '', true)`

// BindTenantParams are the ids ResolveTenant returned.
type BindTenantParams struct {
	MemberID string
	TenantID string
}

// BindTenant binds the tenant and clears app.subject before any domain SQL.
func (q *Queries) BindTenant(ctx context.Context, arg BindTenantParams) error {
	_, err := q.db.Exec(ctx, bindTenant, arg.MemberID, arg.TenantID)
	return err
}

const countActiveTenants = `SELECT count(*) FROM app.tenants WHERE suspended_at IS NULL AND deleted_at IS NULL`

// CountActiveTenants: RLS answers this, not a WHERE clause: the bound tenant
// sees one row at most.
func (q *Queries) CountActiveTenants(ctx context.Context) (int64, error) {
	var n int64
	err := q.db.QueryRow(ctx, countActiveTenants).Scan(&n)
	return n, err
}

const enablePlatform = `SELECT set_config('app.platform', 'on', true)`

// EnablePlatform sets app.platform, which only a platform_admin login turns
// into access.
func (q *Queries) EnablePlatform(ctx context.Context) error {
	_, err := q.db.Exec(ctx, enablePlatform)
	return err
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

// Member is a member row as the API returns it.
type Member struct {
	ID              string    `json:"id"`
	TenantID        *string   `json:"tenantId"`
	Subject         *string   `json:"-"`
	Email           string    `json:"email"`
	DisplayName     string    `json:"displayName"`
	Role            string    `json:"role"`
	IsActive        bool      `json:"isActive"`
	NeedsOnboarding bool      `json:"needsOnboarding"`
	CreatedAt       time.Time `json:"createdAt"`
}

const memberColumns = `id, tenant_id, subject, email, display_name, role, is_active, needs_onboarding, created_at`

func scanMember(row pgx.Row) (Member, error) {
	var m Member
	err := row.Scan(&m.ID, &m.TenantID, &m.Subject, &m.Email, &m.DisplayName, &m.Role,
		&m.IsActive, &m.NeedsOnboarding, &m.CreatedAt)
	return m, err
}

const getOwnMember = `SELECT ` + memberColumns + ` FROM app.members WHERE subject = $1::text`

// GetOwnMember: with only app.subject set (0005), this is the one row
// app_user can see.
func (q *Queries) GetOwnMember(ctx context.Context, subject string) (Member, error) {
	return scanMember(q.db.QueryRow(ctx, getOwnMember, subject))
}

const listMembers = `SELECT ` + memberColumns + ` FROM app.members ORDER BY created_at, id`

// ListMembers returns every member the transaction can see: the bound
// tenant's members.
func (q *Queries) ListMembers(ctx context.Context) ([]Member, error) {
	rows, err := q.db.Query(ctx, listMembers)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Member, error) { return scanMember(r) })
}

const updateMemberRole = `UPDATE app.members SET role = $2 WHERE id = $1 RETURNING ` + memberColumns

// UpdateMemberRole changes a colleague's role; the 0003 trigger requires the
// caller to be an ADMIN. pgx.ErrNoRows means the member is not visible.
func (q *Queries) UpdateMemberRole(ctx context.Context, id, role string) (Member, error) {
	return scanMember(q.db.QueryRow(ctx, updateMemberRole, id, role))
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

// Tenant is a tenant row as the API returns it.
type Tenant struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	Plan        string     `json:"plan"`
	SuspendedAt *time.Time `json:"suspendedAt"`
	CreatedAt   time.Time  `json:"createdAt"`
}

const getTenant = `SELECT id, name, slug, plan, suspended_at, created_at FROM app.tenants WHERE id = $1`

// GetTenant returns the tenant by id if the transaction can see it.
func (q *Queries) GetTenant(ctx context.Context, id string) (Tenant, error) {
	var t Tenant
	err := q.db.QueryRow(ctx, getTenant, id).Scan(&t.ID, &t.Name, &t.Slug, &t.Plan, &t.SuspendedAt, &t.CreatedAt)
	return t, err
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// Project is a project row.
type Project struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenantId"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	CreatedBy  string     `json:"createdBy"`
	ArchivedAt *time.Time `json:"archivedAt"`
	CreatedAt  time.Time  `json:"createdAt"`
}

const projectColumns = `id, tenant_id, name, status, created_by, archived_at, created_at`

func scanProject(row pgx.Row) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Status, &p.CreatedBy, &p.ArchivedAt, &p.CreatedAt)
	return p, err
}

const listProjects = `SELECT ` + projectColumns + ` FROM app.projects ORDER BY created_at DESC, id`

// ListProjects has no tenant filter on purpose: RLS is the filter.
func (q *Queries) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := q.db.Query(ctx, listProjects)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Project, error) { return scanProject(r) })
}

const getProject = `SELECT ` + projectColumns + ` FROM app.projects WHERE id = $1`

// GetProject returns pgx.ErrNoRows for another tenant's project, exactly as
// for one that does not exist.
func (q *Queries) GetProject(ctx context.Context, id string) (Project, error) {
	return scanProject(q.db.QueryRow(ctx, getProject, id))
}

const createProject = `
INSERT INTO app.projects (tenant_id, name, created_by)
VALUES (app.current_tenant_id(), $1, app.current_member_id())
RETURNING ` + projectColumns

// CreateProject creates a project in the bound tenant, as the bound member.
// Neither id comes from the caller.
func (q *Queries) CreateProject(ctx context.Context, name string) (Project, error) {
	return scanProject(q.db.QueryRow(ctx, createProject, name))
}

const setProjectArchived = `
UPDATE app.projects
SET status = CASE WHEN $2::boolean THEN 'archived' ELSE 'active' END,
    archived_at = CASE WHEN $2::boolean THEN clock_timestamp() ELSE NULL END
WHERE id = $1
RETURNING ` + projectColumns

// SetProjectArchived archives or restores; the 0003 trigger requires a
// MANAGER or ADMIN.
func (q *Queries) SetProjectArchived(ctx context.Context, id string, archived bool) (Project, error) {
	return scanProject(q.db.QueryRow(ctx, setProjectArchived, id, archived))
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

// Note is a note row.
type Note struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"projectId"`
	AuthorID  string    `json:"authorId"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"createdAt"`
}

const listNotes = `
SELECT id, project_id, author_id, body, created_at
FROM app.notes WHERE project_id = $1 ORDER BY created_at, id`

// ListNotes lists a project's notes the transaction can see.
func (q *Queries) ListNotes(ctx context.Context, projectID string) ([]Note, error) {
	rows, err := q.db.Query(ctx, listNotes, projectID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Note, error) {
		var n Note
		err := r.Scan(&n.ID, &n.ProjectID, &n.AuthorID, &n.Body, &n.CreatedAt)
		return n, err
	})
}

const createNote = `
INSERT INTO app.notes (tenant_id, project_id, author_id, body)
VALUES (app.current_tenant_id(), $1, app.current_member_id(), $2)
RETURNING id, project_id, author_id, body, created_at`

// CreateNote writes a note as the bound member. A project id from another
// tenant fails the composite foreign key, exactly like one that does not
// exist.
func (q *Queries) CreateNote(ctx context.Context, projectID, body string) (Note, error) {
	var n Note
	err := q.db.QueryRow(ctx, createNote, projectID, body).Scan(&n.ID, &n.ProjectID, &n.AuthorID, &n.Body, &n.CreatedAt)
	return n, err
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

const appendAudit = `
INSERT INTO app.audit_log (tenant_id, actor_id, action, detail)
VALUES (app.current_tenant_id(), app.current_member_id(), $1, $2::jsonb)`

// AppendAudit records an action as the bound member.
func (q *Queries) AppendAudit(ctx context.Context, action string, detailJSON []byte) error {
	if detailJSON == nil {
		detailJSON = []byte(`{}`)
	}
	_, err := q.db.Exec(ctx, appendAudit, action, string(detailJSON))
	return err
}

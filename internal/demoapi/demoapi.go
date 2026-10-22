// Package demoapi is a tiny HTTP API over the kit: every /v1 route verifies
// the bearer token, then runs its SQL inside db.WithTenant. No handler takes
// a tenant id from the request, and no query filters by tenant: RLS does.
package demoapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/treyktw/tenant-rls/auth"
	"github.com/treyktw/tenant-rls/db"
	"github.com/treyktw/tenant-rls/httpapi"
	"github.com/treyktw/tenant-rls/store"
)

// Handler serves the demo routes.
type Handler struct {
	DB       *db.DB
	Verifier auth.TokenVerifier
}

// Router returns the API.
func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(securityHeaders)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := h.DB.Ping(ctx); err != nil {
			httpapi.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/v1", func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler { return auth.Require(h.Verifier, next) })
		r.Method(http.MethodGet, "/me", httpapi.Handle(h.me))
		r.Method(http.MethodGet, "/members", httpapi.Handle(h.listMembers))
		r.Method(http.MethodPatch, "/members/{memberID}", httpapi.Handle(h.updateMemberRole))
		r.Method(http.MethodGet, "/projects", httpapi.Handle(h.listProjects))
		r.Method(http.MethodPost, "/projects", httpapi.Handle(h.createProject))
		r.Method(http.MethodGet, "/projects/{projectID}", httpapi.Handle(h.getProject))
		r.Method(http.MethodPost, "/projects/{projectID}/archive", httpapi.Handle(h.archiveProject))
		r.Method(http.MethodGet, "/projects/{projectID}/notes", httpapi.Handle(h.listNotes))
		r.Method(http.MethodPost, "/projects/{projectID}/notes", httpapi.Handle(h.createNote))
	})

	// Anything else is a JSON 404, not the router's text one.
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httpapi.WriteError(w, r, httpapi.ErrNotFound)
	})
	return r
}

// tenantErr maps what the database said to what the caller may learn. A row
// in another tenant is indistinguishable from a row that does not exist.
func tenantErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, db.ErrNoTenant):
		return httpapi.ErrNoTenant
	case errors.Is(err, pgx.ErrNoRows), db.IsForeignKeyViolation(err):
		return httpapi.ErrNotFound
	case db.IsInsufficientPrivilege(err):
		return httpapi.ErrForbidden
	default:
		return err
	}
}

func subject(r *http.Request) string {
	s, _ := auth.FromContext(r.Context())
	return s.Subject
}

// validUUID keeps malformed ids out of SQL, so they 404 like any other
// unknown id rather than surfacing as a cast error.
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

type meResponse struct {
	Member store.Member  `json:"member"`
	Tenant *store.Tenant `json:"tenant"`
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) error {
	member, err := h.DB.ReadOwnMember(r.Context(), subject(r))
	if errors.Is(err, pgx.ErrNoRows) {
		return httpapi.ErrNoTenant
	}
	if err != nil {
		return err
	}
	resp := meResponse{Member: member}
	if member.TenantID != nil {
		err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{AllowSuspended: true}, func(tx db.Tx, t db.Tenant) error {
			tenant, err := tx.GetTenant(r.Context(), t.TenantID)
			resp.Tenant = &tenant
			return err
		})
		if err != nil && !errors.Is(err, db.ErrNoTenant) {
			return err
		}
	}
	httpapi.WriteJSON(w, http.StatusOK, resp)
	return nil
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) error {
	var members []store.Member
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{}, func(tx db.Tx, _ db.Tenant) error {
		var err error
		members, err = tx.ListMembers(r.Context())
		return err
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"members": members})
	return nil
}

func (h *Handler) updateMemberRole(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "memberID")
	if !validUUID(id) {
		return httpapi.ErrNotFound
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := httpapi.DecodeJSON(r, &body); err != nil {
		return err
	}
	switch body.Role {
	case "ADMIN", "MANAGER", "MEMBER":
	default:
		return httpapi.Invalid("role must be ADMIN, MANAGER or MEMBER")
	}
	var member store.Member
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{Write: true}, func(tx db.Tx, _ db.Tenant) error {
		var err error
		if member, err = tx.UpdateMemberRole(r.Context(), id, body.Role); err != nil {
			return err
		}
		return tx.AppendAudit(r.Context(), "member.role_changed", nil)
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, member)
	return nil
}

func (h *Handler) listProjects(w http.ResponseWriter, r *http.Request) error {
	var projects []store.Project
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{}, func(tx db.Tx, _ db.Tenant) error {
		var err error
		projects, err = tx.ListProjects(r.Context())
		return err
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"projects": projects})
	return nil
}

func (h *Handler) getProject(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "projectID")
	if !validUUID(id) {
		return httpapi.ErrNotFound
	}
	var project store.Project
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{}, func(tx db.Tx, _ db.Tenant) error {
		var err error
		project, err = tx.GetProject(r.Context(), id)
		return err
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, project)
	return nil
}

func (h *Handler) createProject(w http.ResponseWriter, r *http.Request) error {
	var body struct {
		Name string `json:"name"`
	}
	if err := httpapi.DecodeJSON(r, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 200 {
		return httpapi.Invalid("name must be 1-200 characters")
	}
	var project store.Project
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{Write: true}, func(tx db.Tx, _ db.Tenant) error {
		var err error
		if project, err = tx.CreateProject(r.Context(), body.Name); err != nil {
			return err
		}
		return tx.AppendAudit(r.Context(), "project.created", nil)
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusCreated, project)
	return nil
}

func (h *Handler) archiveProject(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "projectID")
	if !validUUID(id) {
		return httpapi.ErrNotFound
	}
	var project store.Project
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{Write: true}, func(tx db.Tx, _ db.Tenant) error {
		var err error
		project, err = tx.SetProjectArchived(r.Context(), id, true)
		return err
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, project)
	return nil
}

func (h *Handler) listNotes(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "projectID")
	if !validUUID(id) {
		return httpapi.ErrNotFound
	}
	var notes []store.Note
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{}, func(tx db.Tx, _ db.Tenant) error {
		// An invisible project is a 404, not an empty list.
		if _, err := tx.GetProject(r.Context(), id); err != nil {
			return err
		}
		var err error
		notes, err = tx.ListNotes(r.Context(), id)
		return err
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"notes": notes})
	return nil
}

func (h *Handler) createNote(w http.ResponseWriter, r *http.Request) error {
	id := chi.URLParam(r, "projectID")
	if !validUUID(id) {
		return httpapi.ErrNotFound
	}
	var body struct {
		Body string `json:"body"`
	}
	if err := httpapi.DecodeJSON(r, &body); err != nil {
		return err
	}
	if strings.TrimSpace(body.Body) == "" || len(body.Body) > 10000 {
		return httpapi.Invalid("body must be 1-10000 characters")
	}
	var note store.Note
	err := h.DB.WithTenant(r.Context(), subject(r), db.TenantOptions{Write: true}, func(tx db.Tx, _ db.Tenant) error {
		// The notes insert policy refuses (42501) a project it cannot see,
		// whether it is another tenant's or does not exist. Look first so
		// both answer 404, and 403 means only "visible but archived".
		if _, err := tx.GetProject(r.Context(), id); err != nil {
			return err
		}
		var err error
		note, err = tx.CreateNote(r.Context(), id, body.Body)
		return err
	})
	if err != nil {
		return tenantErr(err)
	}
	httpapi.WriteJSON(w, http.StatusCreated, note)
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

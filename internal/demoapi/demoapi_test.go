package demoapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/treyktw/tenant-rls/auth"
	"github.com/treyktw/tenant-rls/internal/demoapi"
	"github.com/treyktw/tenant-rls/testdb"
)

var secret = []byte("demoapi-test-secret-FAKEFAKEFAKEFAKE")

type harness struct {
	t   *testing.T
	srv *httptest.Server
}

func newHarness(t *testing.T) harness {
	t.Helper()
	d := testdb.Open(t)
	v, err := auth.NewJWTVerifier(auth.Options{HS256Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&demoapi.Handler{DB: d, Verifier: v}).Router())
	t.Cleanup(srv.Close)
	return harness{t: t, srv: srv}
}

func (h harness) do(subject, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, reader)
	if subject != "" {
		token, err := auth.Sign(secret, "", auth.TokenClaims{Subject: subject, SessionID: "sess_test", TTL: time.Minute})
		if err != nil {
			h.t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func createProject(t *testing.T, tenantID, createdBy, name string) string {
	t.Helper()
	id := testdb.UUID()
	testdb.Platform(t, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO app.projects (id, tenant_id, name, created_by) VALUES ($1, $2, $3, $4)`, id, tenantID, name, createdBy)
		return err
	})
	return id
}

func TestCrossTenantRequestsLookLikeMissingRows(t *testing.T) {
	h := newHarness(t)
	a := testdb.NewFixture(t)
	b := testdb.NewFixture(t)
	projectB := createProject(t, b.TenantID, b.Admin.MemberID, "B's secret project")

	// B sees its own project.
	if code, body := h.do(b.Admin.Subject, "GET", "/v1/projects/"+projectB, nil); code != 200 || body["name"] != "B's secret project" {
		t.Fatalf("owner read: %d %v", code, body)
	}
	// A, even as ADMIN, gets 404 for it on every route, exactly as for an id
	// that does not exist.
	for _, tc := range []struct{ method, path string }{
		{"GET", "/v1/projects/" + projectB},
		{"GET", "/v1/projects/" + projectB + "/notes"},
		{"POST", "/v1/projects/" + projectB + "/archive"},
	} {
		if code, body := h.do(a.Admin.Subject, tc.method, tc.path, nil); code != 404 {
			t.Errorf("%s %s as tenant A: %d %v", tc.method, tc.path, code, body)
		}
	}
	if code, _ := h.do(a.Admin.Subject, "POST", "/v1/projects/"+projectB+"/notes", map[string]string{"body": "planted"}); code != 404 {
		t.Errorf("note on another tenant's project: %d", code)
	}
	if code, _ := h.do(a.Admin.Subject, "PATCH", "/v1/members/"+b.Admin.MemberID, map[string]string{"role": "MEMBER"}); code != 404 {
		t.Errorf("role change on another tenant's member: %d", code)
	}
	unknown := testdb.UUID()
	if code, _ := h.do(a.Admin.Subject, "GET", "/v1/projects/"+unknown, nil); code != 404 {
		t.Errorf("unknown id: %d", code)
	}
	// Lists contain only A's rows.
	_, list := h.do(a.Admin.Subject, "GET", "/v1/projects", nil)
	for _, p := range list["projects"].([]any) {
		if p.(map[string]any)["tenantId"] != a.TenantID {
			t.Errorf("tenant A list contains %v", p)
		}
	}
	_, members := h.do(a.Admin.Subject, "GET", "/v1/members", nil)
	if n := len(members["members"].([]any)); n != 3 {
		t.Errorf("tenant A sees %d members, want its 3", n)
	}
}

func TestWritesRunAsTheCallerUnderTheGates(t *testing.T) {
	h := newHarness(t)
	f := testdb.NewFixture(t)

	code, project := h.do(f.Member.Subject, "POST", "/v1/projects", map[string]string{"name": "Member's project"})
	if code != 201 || project["tenantId"] != f.TenantID || project["createdBy"] != f.Member.MemberID {
		t.Fatalf("create: %d %v", code, project)
	}
	id := project["id"].(string)
	if code, note := h.do(f.Member.Subject, "POST", "/v1/projects/"+id+"/notes", map[string]string{"body": "hello"}); code != 201 || note["authorId"] != f.Member.MemberID {
		t.Fatalf("note: %d %v", code, note)
	}
	// A MEMBER cannot archive (trigger) or change roles (trigger).
	if code, _ := h.do(f.Member.Subject, "POST", "/v1/projects/"+id+"/archive", nil); code != 403 {
		t.Errorf("member archive: %d", code)
	}
	if code, _ := h.do(f.Member.Subject, "PATCH", "/v1/members/"+f.Member.MemberID, map[string]string{"role": "ADMIN"}); code != 403 {
		t.Errorf("member self-promotion: %d", code)
	}
	// A MANAGER archives; then notes are read-only.
	if code, p := h.do(f.Manager.Subject, "POST", "/v1/projects/"+id+"/archive", nil); code != 200 || p["status"] != "archived" {
		t.Errorf("manager archive: %d %v", code, p)
	}
	if code, _ := h.do(f.Member.Subject, "POST", "/v1/projects/"+id+"/notes", map[string]string{"body": "late"}); code != 403 {
		t.Errorf("note on archived project: %d", code)
	}
	// An ADMIN changes roles.
	if code, m := h.do(f.Admin.Subject, "PATCH", "/v1/members/"+f.Member.MemberID, map[string]string{"role": "MANAGER"}); code != 200 || m["role"] != "MANAGER" {
		t.Errorf("admin role change: %d %v", code, m)
	}
}

func TestAuthenticationAndTenantBinding(t *testing.T) {
	h := newHarness(t)
	f := testdb.NewFixture(t)

	if code, _ := h.do("", "GET", "/v1/projects", nil); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, body := h.do("user_kittest_nobody", "GET", "/v1/projects", nil); code != 403 || body["error"].(map[string]any)["code"] != "no_tenant" {
		t.Errorf("unknown subject: %d %v", code, body)
	}
	if code, _ := h.do(f.Unbound.Subject, "GET", "/v1/projects", nil); code != 403 {
		t.Errorf("unbound subject: %d", code)
	}
	if code, body := h.do(f.Unbound.Subject, "GET", "/v1/me", nil); code != 200 || body["tenant"] != nil {
		t.Errorf("unbound /me: %d %v", code, body)
	}
	if code, body := h.do(f.Admin.Subject, "GET", "/v1/me", nil); code != 200 || body["tenant"].(map[string]any)["id"] != f.TenantID {
		t.Errorf("admin /me: %d %v", code, body)
	}
	if code, _ := h.do(f.Admin.Subject, "GET", "/v1/projects/not-a-uuid", nil); code != 404 {
		t.Errorf("malformed id: %d", code)
	}
}

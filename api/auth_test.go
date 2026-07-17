package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func TestSetWebSessionCookies(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		secure    bool
	}{
		{name: "http development", publicURL: "http://localhost:42080", secure: false},
		{name: "https", publicURL: "https://airlock.example.com", secure: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			setWebSessionCookies(w, tt.publicURL, "access", "refresh")

			cookies := w.Result().Cookies()
			if len(cookies) != 2 {
				t.Fatalf("cookies = %v, want two", cookies)
			}
			for _, cookie := range cookies {
				if cookie.Secure != tt.secure || !cookie.HttpOnly || cookie.Domain != "" {
					t.Errorf("cookie = %#v", cookie)
				}
			}
			if cookies[0].SameSite != http.SameSiteLaxMode || cookies[1].SameSite != http.SameSiteStrictMode {
				t.Errorf("SameSite access=%v refresh=%v", cookies[0].SameSite, cookies[1].SameSite)
			}
		})
	}
}

func TestActivateIsAtomicAcrossConcurrentRequests(t *testing.T) {
	skipIfNoDB(t)
	ctx := context.Background()
	q := dbq.New(testDB.Pool())
	const code = "activation-secret"
	if _, err := q.SetActivationCode(ctx, pgtype.Text{String: code, Valid: true}); err != nil {
		t.Fatalf("SetActivationCode: %v", err)
	}
	h := NewAuthHandler(testDB, testJWTSecret, "", "https://airlock.test", zap.NewNop())

	statuses := make([]int, 2)
	var wg sync.WaitGroup
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/auth/activate", strings.NewReader(`{"email":"admin@example.com","displayName":"Admin","activationCode":"`+code+`"}`))
			rec := httptest.NewRecorder()
			h.Activate(rec, req)
			statuses[i] = rec.Code
		}()
	}
	wg.Wait()
	sort.Ints(statuses)
	if statuses[0] != http.StatusCreated || statuses[1] != http.StatusConflict {
		t.Fatalf("activation statuses = %v, want [201 409]", statuses)
	}

	var tenants, users, sessions int
	if err := testDB.Pool().QueryRow(ctx, `SELECT (SELECT count(*) FROM tenants), (SELECT count(*) FROM users), (SELECT count(*) FROM user_sessions)`).Scan(&tenants, &users, &sessions); err != nil {
		t.Fatal(err)
	}
	if tenants != 1 || users != 1 || sessions != 1 {
		t.Fatalf("rows = tenants %d users %d sessions %d, want one each", tenants, users, sessions)
	}
	settings, err := q.GetSystemSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ActivationCode.Valid {
		t.Fatal("activation code was not consumed")
	}
}

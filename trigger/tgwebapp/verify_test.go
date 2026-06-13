package tgwebapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testBotToken = "123456:ABCDEF"

// sign builds a valid initData string signed by botToken. fields must
// include auth_date and user.
func sign(t *testing.T, botToken string, fields map[string]string) string {
	t.Helper()
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(fields[k])
	}
	secret := hmac.New(sha256.New, []byte("WebAppData"))
	secret.Write([]byte(botToken))
	mac := hmac.New(sha256.New, secret.Sum(nil))
	mac.Write([]byte(sb.String()))
	hash := hex.EncodeToString(mac.Sum(nil))

	v := url.Values{}
	for k, val := range fields {
		v.Set(k, val)
	}
	v.Set("hash", hash)
	return v.Encode()
}

func TestVerify_Valid(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	data := sign(t, testBotToken, map[string]string{
		"auth_date": strconv.FormatInt(now.Add(-10*time.Second).Unix(), 10),
		"user":      `{"id":42,"username":"alice","first_name":"Alice"}`,
		"query_id":  "AAH0123",
	})
	u, err := Verify(data, testBotToken, 5*time.Minute, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if u.ID != 42 || u.Username != "alice" || u.FirstName != "Alice" {
		t.Errorf("user mismatch: %+v", u)
	}
}

func TestVerify_TamperedHash(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	data := sign(t, testBotToken, map[string]string{
		"auth_date": strconv.FormatInt(now.Unix(), 10),
		"user":      `{"id":42}`,
	})
	// Flip a bit in the hash.
	tampered := strings.Replace(data, "hash=", "hash=ffffffff", 1)
	if _, err := Verify(tampered, testBotToken, 5*time.Minute, now); err == nil {
		t.Fatal("expected hash-mismatch error, got nil")
	}
}

func TestVerify_WrongBotToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	data := sign(t, testBotToken, map[string]string{
		"auth_date": strconv.FormatInt(now.Unix(), 10),
		"user":      `{"id":42}`,
	})
	if _, err := Verify(data, "999999:DIFFERENT", 5*time.Minute, now); err == nil {
		t.Fatal("expected mismatch with wrong token, got nil")
	}
}

func TestVerify_Expired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	data := sign(t, testBotToken, map[string]string{
		"auth_date": strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10),
		"user":      `{"id":42}`,
	})
	if _, err := Verify(data, testBotToken, 5*time.Minute, now); err == nil {
		t.Fatal("expected expired error, got nil")
	}
}

func TestVerify_MissingFields(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name   string
		fields map[string]string
	}{
		{"no auth_date", map[string]string{"user": `{"id":1}`}},
		{"no user", map[string]string{"auth_date": strconv.FormatInt(now.Unix(), 10)}},
		{"zero user id", map[string]string{
			"auth_date": strconv.FormatInt(now.Unix(), 10),
			"user":      `{"id":0}`,
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			data := sign(t, testBotToken, tt.fields)
			if _, err := Verify(data, testBotToken, 5*time.Minute, now); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestVerify_NoHashField(t *testing.T) {
	if _, err := Verify("auth_date=1&user=%7B%22id%22%3A1%7D", testBotToken, 5*time.Minute, time.Now()); err == nil {
		t.Fatal("expected missing-hash error, got nil")
	}
}

func TestVerify_EmptyBotToken(t *testing.T) {
	if _, err := Verify("hash=abc", "", 5*time.Minute, time.Now()); err == nil {
		t.Fatal("expected empty-token error, got nil")
	}
}

func TestVerify_MalformedEncoding(t *testing.T) {
	if _, err := Verify("%ZZ", testBotToken, 5*time.Minute, time.Now()); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

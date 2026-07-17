// Package tgwebapp verifies Telegram Web App initData payloads.
//
// Telegram Web Apps deliver an HMAC-signed initData string to the page that
// the bot's web_app button opens. The signature is derived from the bot
// token, so any server holding the bot token can authenticate the user
// without a password. This package implements the verification algorithm
// from https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app.
package tgwebapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// User is the subset of Telegram's WebAppUser that callers care about.
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// Verify validates a Telegram Web App initData string against botToken.
// The algorithm:
//
//  1. Parse initData as application/x-www-form-urlencoded.
//  2. Remove the `hash` field; sort remaining fields alphabetically and
//     join them as "k=v\nk=v\n..." (data_check_string).
//  3. secret_key = HMAC-SHA256(key="WebAppData", msg=botToken).
//  4. expected = hex(HMAC-SHA256(key=secret_key, msg=data_check_string)).
//  5. Constant-time compare with the `hash` field.
//  6. Enforce now - auth_date <= maxAge.
//  7. Decode the `user` field (a JSON object) into User.
//
// Returns the parsed User on success.
func Verify(initData, botToken string, maxAge time.Duration, now time.Time) (User, error) {
	if botToken == "" {
		return User{}, errors.New("tgwebapp: empty bot token")
	}

	values, err := url.ParseQuery(initData)
	if err != nil {
		return User{}, fmt.Errorf("tgwebapp: parse initData: %w", err)
	}

	gotHash := values.Get("hash")
	if gotHash == "" {
		return User{}, errors.New("tgwebapp: missing hash field")
	}
	values.Del("hash")

	keys := make([]string, 0, len(values))
	for k := range values {
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
		sb.WriteString(values.Get(k))
	}
	dataCheckString := sb.String()

	secretMAC := hmac.New(sha256.New, []byte("WebAppData"))
	secretMAC.Write([]byte(botToken))
	secretKey := secretMAC.Sum(nil)

	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(dataCheckString))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(gotHash), []byte(expected)) {
		return User{}, errors.New("tgwebapp: hash mismatch")
	}

	authDateStr := values.Get("auth_date")
	if authDateStr == "" {
		return User{}, errors.New("tgwebapp: missing auth_date")
	}
	authDateUnix, err := strconv.ParseInt(authDateStr, 10, 64)
	if err != nil {
		return User{}, fmt.Errorf("tgwebapp: parse auth_date: %w", err)
	}
	authDate := time.Unix(authDateUnix, 0)
	if authDate.After(now) {
		return User{}, fmt.Errorf("tgwebapp: auth_date is in the future by %s", authDate.Sub(now))
	}
	if now.Sub(authDate) > maxAge {
		return User{}, fmt.Errorf("tgwebapp: auth_date expired (age %s, max %s)", now.Sub(authDate), maxAge)
	}

	userJSON := values.Get("user")
	if userJSON == "" {
		return User{}, errors.New("tgwebapp: missing user field")
	}
	var u User
	if err := json.Unmarshal([]byte(userJSON), &u); err != nil {
		return User{}, fmt.Errorf("tgwebapp: decode user: %w", err)
	}
	if u.ID == 0 {
		return User{}, errors.New("tgwebapp: user.id is zero")
	}
	return u, nil
}

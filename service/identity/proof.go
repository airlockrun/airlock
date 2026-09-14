package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
)

type linkProof struct {
	service   *Service
	platform  string
	bridgeID  uuid.UUID
	uid       string
	hash      string
	expiresAt time.Time
}

// WithLinkSecret creates an immutable configured service at composition time.
// List and Unlink need no link-signing key; VerifyLink requires one.
func (s *Service) WithLinkSecret(secret string) *Service {
	if s == nil || secret == "" {
		panic("identity: service and link secret are required")
	}
	configured := *s
	configured.linkSecret = secret
	return &configured
}

// VerifyLink verifies the existing bridge-signed link profile and returns an
// opaque service-bound proof. Neither a transport nor a direct service caller
// can replace its subject, challenge hash, or expiry with scalar assertions.
func (s *Service) VerifyLink(platform, bridge, uid, timestamp, signature string) (PreviewInput, error) {
	if s.linkSecret == "" {
		panic("identity: link verifier is not configured")
	}
	id, err := uuid.Parse(bridge)
	if err != nil || id == uuid.Nil || id.String() != bridge || platform != "telegram" || uid == "" || strings.Contains(uid, ":") {
		return PreviewInput{}, service.Detail(service.ErrInvalidInput, "invalid identity link")
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(ts, 10) != timestamp {
		return PreviewInput{}, service.Detail(service.ErrInvalidInput, "invalid timestamp")
	}
	now := time.Now()
	if ts < now.Unix()-600 || ts > now.Unix()+60 {
		return PreviewInput{}, service.Detail(service.ErrInvalidInput, "link has expired")
	}
	issued := time.Unix(ts, 0)
	expires := issued.Add(10 * time.Minute)
	if issued.After(now.Add(time.Minute)) || !expires.After(now) {
		return PreviewInput{}, service.Detail(service.ErrInvalidInput, "link has expired")
	}
	payload := platform + ":" + bridge + ":" + uid + ":" + timestamp
	mac := hmac.New(sha256.New, []byte(s.linkSecret))
	mac.Write([]byte(payload))
	if !hmac.Equal([]byte(signature), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return PreviewInput{}, service.Detail(service.ErrInvalidInput, "invalid signature")
	}
	sum := sha256.Sum256([]byte(payload + ":" + signature))
	hash := hex.EncodeToString(sum[:])
	return PreviewInput{Platform: platform, BridgeID: id, UID: uid, ChallengeHash: hash, ExpiresAt: expires,
		proof: &linkProof{service: s, platform: platform, bridgeID: id, uid: uid, hash: hash, expiresAt: expires}}, nil
}

func (in PreviewInput) validProof(s *Service) bool {
	p := in.proof
	return p != nil && p.service == s && p.platform == in.Platform && p.bridgeID == in.BridgeID &&
		p.uid == in.UID && p.hash == in.ChallengeHash && p.expiresAt.After(time.Now()) &&
		(in.ExpiresAt.IsZero() || in.ExpiresAt.Equal(p.expiresAt))
}

func (in PreviewInput) ForLink() LinkInput {
	return LinkInput{Platform: in.Platform, BridgeID: in.BridgeID, UID: in.UID, ChallengeHash: in.ChallengeHash, proof: in.proof}
}

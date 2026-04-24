package trigger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
)

func TestTelegramGetChat(t *testing.T) {
	var lastMethod, lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod = r.URL.Path
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if v, ok := body["chat_id"].(string); ok {
			lastBody = v
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"result": map[string]any{
				"id":         99001122,
				"username":   "alice",
				"first_name": "Alice",
				"last_name":  "Example",
			},
		})
	}))
	defer srv.Close()

	td := NewTelegramDriverWithBaseURL(srv.URL, srv.Client())
	info, err := td.GetChat(context.Background(), "test-token", "99001122")
	if err != nil {
		t.Fatalf("GetChat: %v", err)
	}

	if info.Username != "alice" {
		t.Errorf("Username = %q, want alice", info.Username)
	}
	if info.FirstName != "Alice" {
		t.Errorf("FirstName = %q, want Alice", info.FirstName)
	}
	if info.LastName != "Example" {
		t.Errorf("LastName = %q, want Example", info.LastName)
	}
	if !strings.HasSuffix(lastMethod, "/getChat") {
		t.Errorf("method path = %q, want .../getChat", lastMethod)
	}
	if lastBody != "99001122" {
		t.Errorf("chat_id in body = %q, want 99001122", lastBody)
	}
}

func TestTelegramGetChatNotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "chat not found"})
	}))
	defer srv.Close()

	td := NewTelegramDriverWithBaseURL(srv.URL, srv.Client())
	_, err := td.GetChat(context.Background(), "test-token", "123")
	if err == nil {
		t.Fatal("expected error when ok=false, got nil")
	}
}

// TestTelegramPollMediaExtraction verifies Poll() extracts voice, audio,
// video_note, and video attachments from a single update batch and flags
// voice notes for auto-transcription.
func TestTelegramPollMediaExtraction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Serve file content for the file download step.
		if strings.HasPrefix(r.URL.Path, "/file/") {
			w.Header().Set("Content-Type", "application/octet-stream")
			// Embed the file_path segment into the bytes so tests can
			// confirm which file came back.
			_, _ = w.Write([]byte("bytes-for-" + strings.TrimPrefix(r.URL.Path, "/file/bottest-token/")))
			return
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"result": []map[string]any{
					{
						"update_id": 1,
						"message": map[string]any{
							"message_id": 10,
							"from":       map[string]any{"id": 42, "first_name": "Alice"},
							"chat":       map[string]any{"id": 42, "type": "private"},
							"voice": map[string]any{
								"file_id":   "voice-1",
								"duration":  3,
								"mime_type": "audio/ogg",
								"file_size": 1024,
							},
						},
					},
					{
						"update_id": 2,
						"message": map[string]any{
							"message_id": 11,
							"from":       map[string]any{"id": 42, "first_name": "Alice"},
							"chat":       map[string]any{"id": 42, "type": "private"},
							"audio": map[string]any{
								"file_id":   "audio-1",
								"duration":  120,
								"mime_type": "audio/mpeg",
								"file_name": "song.mp3",
								"file_size": 4096,
							},
						},
					},
					{
						"update_id": 3,
						"message": map[string]any{
							"message_id": 12,
							"from":       map[string]any{"id": 42, "first_name": "Alice"},
							"chat":       map[string]any{"id": 42, "type": "private"},
							"video_note": map[string]any{
								"file_id":   "vn-1",
								"duration":  5,
								"file_size": 8192,
							},
						},
					},
					{
						"update_id": 4,
						"message": map[string]any{
							"message_id": 13,
							"from":       map[string]any{"id": 42, "first_name": "Alice"},
							"chat":       map[string]any{"id": 42, "type": "private"},
							"video": map[string]any{
								"file_id":   "vid-1",
								"duration":  30,
								"mime_type": "video/mp4",
								"file_name": "clip.mp4",
								"file_size": 16384,
							},
						},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/getFile"):
			var body struct {
				FileID string `json:"file_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true,
				"result": map[string]any{
					"file_path": body.FileID + ".bin",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	td := NewTelegramDriverWithBaseURL(srv.URL, srv.Client())
	br := &dbq.Bridge{TokenEncrypted: "test-token"}
	events, err := td.Poll(context.Background(), br)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4", len(events))
	}

	// Event 0: voice — must be flagged.
	if len(events[0].Files) != 1 {
		t.Fatalf("voice event files = %d, want 1", len(events[0].Files))
	}
	vf := events[0].Files[0]
	if !vf.IsVoiceNote {
		t.Error("voice file: IsVoiceNote = false, want true")
	}
	if vf.ContentType != "audio/ogg" {
		t.Errorf("voice file: ContentType = %q, want audio/ogg", vf.ContentType)
	}
	if vf.Filename != "voice.ogg" {
		t.Errorf("voice file: Filename = %q, want voice.ogg", vf.Filename)
	}

	// Event 1: audio — must NOT be flagged.
	if len(events[1].Files) != 1 {
		t.Fatalf("audio event files = %d, want 1", len(events[1].Files))
	}
	af := events[1].Files[0]
	if af.IsVoiceNote {
		t.Error("audio file: IsVoiceNote = true, want false")
	}
	if af.Filename != "song.mp3" {
		t.Errorf("audio file: Filename = %q, want song.mp3", af.Filename)
	}

	// Event 2: video_note — must NOT be flagged, forced to video/mp4.
	if len(events[2].Files) != 1 {
		t.Fatalf("video_note event files = %d, want 1", len(events[2].Files))
	}
	vn := events[2].Files[0]
	if vn.IsVoiceNote {
		t.Error("video_note file: IsVoiceNote = true, want false")
	}
	if vn.ContentType != "video/mp4" {
		t.Errorf("video_note file: ContentType = %q, want video/mp4", vn.ContentType)
	}

	// Event 3: video — must NOT be flagged.
	if len(events[3].Files) != 1 {
		t.Fatalf("video event files = %d, want 1", len(events[3].Files))
	}
	if events[3].Files[0].IsVoiceNote {
		t.Error("video file: IsVoiceNote = true, want false")
	}
}

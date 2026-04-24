// Package audio centralises audio-format conversion so every transcription
// entry point (bridge voice notes, agent-invoked /api/agent/llm/transcribe)
// normalises to a format every STT model accepts.
package audio

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// sttWhitelist lists the container formats OpenAI's STT models accept
// directly (gpt-4o-transcribe + whisper). Anything outside this set —
// ogg/opus, flac, video containers like mov/avi/mkv — is transcoded to
// MP3 via ffmpeg. Video inputs come out as audio-only MP3 because the
// ffmpeg pipeline selects `-f mp3`, implicitly stripping the video track.
//
// Detection is by magic bytes, not filename, so the check survives
// renames and misleading extensions.
func detectSTTFormat(b []byte) string {
	switch {
	case len(b) >= 3 && bytes.Equal(b[:3], []byte("ID3")):
		return "mp3" // ID3-tagged MP3
	case len(b) >= 2 && b[0] == 0xFF && (b[1]&0xE0) == 0xE0:
		return "mp3" // MPEG audio frame sync
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WAVE")):
		return "wav"
	case len(b) >= 8 && bytes.Equal(b[4:8], []byte("ftyp")):
		return "mp4" // covers mp4, m4a, mov (ftyp brand varies, but OpenAI accepts all ISO-BMFF)
	case len(b) >= 4 && b[0] == 0x1A && b[1] == 0x45 && b[2] == 0xDF && b[3] == 0xA3:
		return "webm" // EBML — covers webm and matroska
	}
	return ""
}

// NormalizeForSTT converts audio bytes to a format every OpenAI STT model
// accepts (MP3). Formats already on the STT whitelist pass through unchanged.
// Ogg/opus (Telegram voice notes), FLAC, video containers (mov, avi, mkv,
// non-ISO-BMFF wrappers) are transcoded. On transcoder failure — notably
// when ffmpeg is missing — the original bytes are returned so whisper-1
// (which accepts ogg natively) still works in degraded setups.
func NormalizeForSTT(ctx context.Context, audio []byte, filename, mime string) (outAudio []byte, outFilename, outMime string, err error) {
	if detectSTTFormat(audio) != "" {
		return audio, filename, mime, nil
	}
	mp3, tErr := transcodeToMP3(ctx, audio)
	if tErr != nil {
		return audio, filename, mime, tErr
	}
	return mp3, stripExt(filename) + ".mp3", "audio/mpeg", nil
}

// transcodeToMP3 reencodes arbitrary audio/video bytes to MP3 via the system
// ffmpeg binary. When the input is a video container, ffmpeg's `-f mp3`
// pipeline discards the video track and emits the audio stream. Requires
// `ffmpeg` on PATH.
func transcodeToMP3(ctx context.Context, in []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-hide_banner", "-loglevel", "error",
		"-i", "pipe:0",
		"-vn",              // drop any video track — STT only needs audio
		"-f", "mp3",
		"-acodec", "libmp3lame",
		"-q:a", "4", // VBR ~165kbps — plenty for speech, smaller than the default
		"pipe:1",
	)
	cmd.Stdin = bytes.NewReader(in)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ffmpeg: %w (stderr: %s)", err, errBuf.String())
	}
	return out.Bytes(), nil
}

func stripExt(name string) string {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}

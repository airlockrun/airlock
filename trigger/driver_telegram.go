package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"go.uber.org/zap"
)

// TelegramDriver handles Telegram bridges via long-polling.
type TelegramDriver struct {
	httpClient *http.Client
	baseURL    string // default: "https://api.telegram.org", override for testing
	logger     *zap.Logger
}

// NewTelegramDriver creates a TelegramDriver. logger is used to surface
// Telegram API errors (notably the silent-failure Markdown/HTML parse
// rejections that otherwise vanish). Pass zap.NewNop() in tests.
//
// The HTTP client's Timeout caps the entire request — connect, TLS,
// upload, server processing, response body read. Sized to comfortably
// cover the long-poll getUpdates window (timeout=30s server-side) plus
// TLS/network slack, while still releasing a goroutine if a connection
// stalls on a short call (sendMessage, getMe, …). Without a ceiling
// here those short calls can hang indefinitely on a half-open TCP
// socket — the kind of failure that happens on a local network blip
// (WG/VPN reconnect, NIC cycle) when the OS hasn't yet noticed the
// peer is gone.
func NewTelegramDriver(logger *zap.Logger) *TelegramDriver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &TelegramDriver{
		httpClient: &http.Client{Timeout: 60 * time.Second},
		logger:     logger,
	}
}

// NewTelegramDriverWithBaseURL creates a TelegramDriver with a custom base URL and HTTP client (for testing).
func NewTelegramDriverWithBaseURL(baseURL string, client *http.Client) *TelegramDriver {
	return &TelegramDriver{httpClient: client, baseURL: baseURL, logger: zap.NewNop()}
}

func (d *TelegramDriver) Init(ctx context.Context, br *dbq.Bridge) error {
	token := br.BotTokenRef // caller decrypts before passing to driver

	// Get the latest update offset so the first poll skips stale messages.
	updates, err := d.getUpdates(ctx, token, -1, 0)
	if err != nil {
		return nil // non-fatal
	}
	if len(updates) > 0 {
		cfg := telegramConfig{Offset: updates[len(updates)-1].UpdateID + 1}
		br.Config = mustJSON(cfg)
	}
	return nil
}

func (d *TelegramDriver) Activate(ctx context.Context, br dbq.Bridge) error {
	token := br.BotTokenRef // caller decrypts before passing to driver
	// Delete any existing webhook to ensure clean long-poll state.
	return d.callTelegram(ctx, token, "deleteWebhook", nil)
}

// Teardown clears the bot's chat menu button so a deleted or disabled bridge
// doesn't leave a dead web-app "Open" button in Telegram (setChatMenuButton is
// bot-global server-side state that otherwise persists). br.BotTokenRef must be
// the decrypted bot token — BridgeManager.TeardownBridge resolves it.
func (d *TelegramDriver) Teardown(ctx context.Context, br dbq.Bridge) error {
	return d.SetMenuButton(ctx, br.BotTokenRef, "")
}

// DefaultEcho reports that Telegram defaults to hiding tool bubbles: each
// tool-call / tool-result is rendered as its own chat message and a chatty
// agent quickly swamps the conversation. Users can opt in per-chat with
// `/echo on`.
func (d *TelegramDriver) DefaultEcho() bool { return false }

// RegisterCommands publishes the slash-command registry to Telegram's
// global command menu via setMyCommands. Telegram stores names without
// the leading slash.
func (d *TelegramDriver) RegisterCommands(ctx context.Context, br dbq.Bridge, cmds []SlashCommand) error {
	token := br.BotTokenRef
	tgCmds := make([]map[string]string, len(cmds))
	for i, c := range cmds {
		tgCmds[i] = map[string]string{
			"command":     c.Name,
			"description": c.Description,
		}
	}
	return d.callTelegram(ctx, token, "setMyCommands", map[string]any{
		"commands": tgCmds,
	})
}

func (d *TelegramDriver) Poll(ctx context.Context, br *dbq.Bridge) ([]BridgeEvent, error) {
	token := br.BotTokenRef // caller decrypts

	// Read offset from bridge config.
	var cfg telegramConfig
	json.Unmarshal(br.Config, &cfg)

	updates, err := d.getUpdates(ctx, token, cfg.Offset, 30)
	if err != nil {
		return nil, err
	}

	var events []BridgeEvent
	// advanceOffset must be called for EVERY update we observe — even ones we
	// can't act on — or getUpdates will keep re-delivering them forever.
	advanceOffset := func(updateID int64) {
		if updateID >= cfg.Offset {
			cfg.Offset = updateID + 1
		}
	}
	for _, u := range updates {
		// Inline-keyboard button tap — route as a BridgeCallback.
		if u.CallbackQuery != nil {
			cq := u.CallbackQuery
			// DM-only: drop callbacks from non-private chats. The bot
			// shouldn't be answering button taps in groups today.
			if cq.Message == nil || cq.Message.Chat.Type != "private" {
				advanceOffset(u.UpdateID)
				continue
			}
			events = append(events, BridgeEvent{
				BridgeID:   pgUUID(br.ID),
				ExternalID: strconv.FormatInt(cq.Message.Chat.ID, 10),
				SenderID:   strconv.FormatInt(cq.From.ID, 10),
				SenderName: cq.From.FirstName,
				Callback: &BridgeCallback{
					Data:      cq.Data,
					AckID:     cq.ID,
					MessageID: strconv.FormatInt(cq.Message.MessageID, 10),
				},
				RawPayload: mustJSON(u),
			})
			advanceOffset(u.UpdateID)
			continue
		}

		if u.Message == nil {
			advanceOffset(u.UpdateID)
			continue
		}
		// Managed-bot creation service message — surface it for manager
		// bridges (HandleEvent ignores it on non-manager bridges). Handled
		// before the private-chat filter since it's a service message.
		if mbc := u.Message.ManagedBotCreated; mbc != nil && mbc.Bot.ID != 0 {
			events = append(events, BridgeEvent{
				BridgeID:   pgUUID(br.ID),
				ManagedBot: &ManagedBotEvent{BotID: mbc.Bot.ID, Username: mbc.Bot.Username},
				RawPayload: mustJSON(u),
			})
			advanceOffset(u.UpdateID)
			continue
		}
		// DM-only: drop messages from groups, supergroups, channels.
		if u.Message.Chat.Type != "private" {
			advanceOffset(u.UpdateID)
			continue
		}
		ev := BridgeEvent{
			BridgeID:          pgUUID(br.ID),
			ExternalID:        strconv.FormatInt(u.Message.Chat.ID, 10),
			SenderID:          strconv.FormatInt(u.Message.From.ID, 10),
			SenderName:        u.Message.From.FirstName,
			Text:              u.Message.Text,
			ReferencedMessage: telegramReferenced(u.Message),
			RawPayload:        mustJSON(u),
		}

		// Use caption as text if message has media but no text.
		if ev.Text == "" && u.Message.Caption != "" {
			ev.Text = u.Message.Caption
		}

		// Extract photo (pick largest size).
		if len(u.Message.Photo) > 0 {
			largest := u.Message.Photo[len(u.Message.Photo)-1]
			data, err := d.downloadFile(ctx, token, largest.FileID)
			if err == nil {
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      largest.FileID,
					Filename:    "photo.jpg",
					ContentType: "image/jpeg",
					Size:        largest.FileSize,
					Data:        data,
				})
			}
		}

		// Extract document.
		if u.Message.Document != nil {
			doc := u.Message.Document
			data, err := d.downloadFile(ctx, token, doc.FileID)
			if err == nil {
				ct := doc.MimeType
				if ct == "" {
					ct = "application/octet-stream"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      doc.FileID,
					Filename:    doc.FileName,
					ContentType: ct,
					Size:        doc.FileSize,
					Data:        data,
				})
			}
		}

		// Extract voice note — tagged for auto-transcription in the bridge layer.
		if u.Message.Voice != nil {
			v := u.Message.Voice
			data, err := d.downloadFile(ctx, token, v.FileID)
			if err == nil {
				ct := v.MimeType
				if ct == "" {
					ct = "audio/ogg"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      v.FileID,
					Filename:    "voice.ogg",
					ContentType: ct,
					Size:        v.FileSize,
					Data:        data,
					IsVoiceNote: true,
				})
			}
		}

		// Extract audio file — passed through as plain attachment.
		if u.Message.Audio != nil {
			a := u.Message.Audio
			data, err := d.downloadFile(ctx, token, a.FileID)
			if err == nil {
				ct := a.MimeType
				if ct == "" {
					ct = "audio/mpeg"
				}
				name := a.FileName
				if name == "" {
					name = "audio"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      a.FileID,
					Filename:    name,
					ContentType: ct,
					Size:        a.FileSize,
					Data:        data,
				})
			}
		}

		// Extract video note — plain attachment.
		if u.Message.VideoNote != nil {
			vn := u.Message.VideoNote
			data, err := d.downloadFile(ctx, token, vn.FileID)
			if err == nil {
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      vn.FileID,
					Filename:    "video_note.mp4",
					ContentType: "video/mp4",
					Size:        vn.FileSize,
					Data:        data,
				})
			}
		}

		// Extract video — plain attachment.
		if u.Message.Video != nil {
			vid := u.Message.Video
			data, err := d.downloadFile(ctx, token, vid.FileID)
			if err == nil {
				ct := vid.MimeType
				if ct == "" {
					ct = "video/mp4"
				}
				name := vid.FileName
				if name == "" {
					name = "video.mp4"
				}
				ev.Files = append(ev.Files, BridgeFile{
					FileID:      vid.FileID,
					Filename:    name,
					ContentType: ct,
					Size:        vid.FileSize,
					Data:        data,
				})
			}
		}

		events = append(events, ev)
		advanceOffset(u.UpdateID)
	}

	// Persist updated offset back to bridge config.
	br.Config = mustJSON(cfg)

	return events, nil
}

func (d *TelegramDriver) SendStream(ctx context.Context, br dbq.Bridge, externalID string, echo bool, events <-chan ResponseEvent) (string, error) {
	token := br.BotTokenRef
	chatID, err := strconv.ParseInt(externalID, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid chat ID %q: %w", externalID, err)
	}

	// Keep a "typing…" indicator alive for the duration of the stream.
	// Telegram clears the action after ~5s or when the bot sends a message,
	// so we refresh it on a 4s ticker. Sending an initial action right away
	// makes the indicator appear before the first LLM token lands.
	stopTyping := d.keepTyping(ctx, token, chatID)
	defer stopTyping()

	// runEndedCh closes when this SendStream returns. The cancel-button
	// goroutine watches it to know when to delete its message.
	runEndedCh := make(chan struct{})
	defer close(runEndedCh)

	var sb strings.Builder

	// flushText sends the accumulated text as a final message and resets for the
	// next segment. LLM output is markdown — sent as a Rich Message so tables,
	// headings, lists, and quotes render natively (verbatim, no conversion).
	flushText := func() {
		text := sb.String()
		if text != "" {
			_, _ = d.sendRichMessage(ctx, token, chatID, text, nil)
			sb.Reset()
		}
	}

	for ev := range events {
		switch ev.Type {
		case "run_started":
			go d.scheduleCancelButton(ctx, token, chatID, ev.RunID, runEndedCh)

		case "text-delta":
			sb.WriteString(ev.Text)

		case "tool-call":
			// When echo is off, tool-call bubbles are suppressed — in quiet
			// mode the user only sees errors and final text. Flush pending
			// text either way so it doesn't get deferred behind a tool block
			// that never renders.
			flushText()
			if echo {
				msg := formatToolCall(ev.ToolName, ev.ToolInput)
				_, _ = d.sendRichMessage(ctx, token, chatID, msg, nil)
			}

		case "tool-result", "tool-error":
			// Errors always render. Successful tool-results obey echo —
			// they're the "run_js output took over my chat" noise users
			// want to silence.
			isError := ev.Type == "tool-error" || ev.ToolError != ""
			if !echo && !isError {
				continue
			}
			msg := formatToolResult(ev.ToolName, ev.ToolOutput, ev.ToolError)
			_, _ = d.sendRichMessage(ctx, token, chatID, msg, nil)

		case "confirmation_required":
			flushText()
			text := formatConfirmation(ev.Description, ev.Permission, ev.Patterns, ev.Code)
			kb := approvalKeyboard(ev.RunID)
			_, _ = d.sendRichMessage(ctx, token, chatID, text, kb)

		case "info":
			flushText()
			if ev.Text != "" {
				_, _ = d.sendRichMessage(ctx, token, chatID, ev.Text, nil)
			}
		}
	}

	// Finalize remaining text.
	flushText()

	return sb.String(), nil
}

// codeFence wraps text in a Rich Markdown fenced code block — the rich
// renderer's fixed-width block, the markdown analogue of the old <pre>.
func codeFence(s string) string {
	return "```\n" + s + "\n```"
}

// formatToolCall formats a tool call as Rich Markdown.
func formatToolCall(toolName, input string) string {
	var sb strings.Builder
	sb.WriteString("▶ **")
	sb.WriteString(toolName)
	sb.WriteString("**")
	if input != "" {
		// For single-arg tools, show just the value.
		val := input
		var args map[string]any
		if json.Unmarshal([]byte(input), &args) == nil && len(args) == 1 {
			for _, v := range args {
				val = fmt.Sprint(v)
			}
		}
		sb.WriteString("\n")
		sb.WriteString(codeFence(val))
	}
	return sb.String()
}

// formatConfirmation renders the approval prompt body as Rich Markdown. Buttons
// are attached separately via reply_markup. Patterns are intentionally omitted
// from the UI — for run_js they're "*", and for tools where they'd be
// meaningful (bash, edit) the same info is either in the command/path already
// embedded in code or not useful to the end user reviewing.
func formatConfirmation(description, permission string, patterns []string, code string) string {
	_ = patterns
	var sb strings.Builder
	sb.WriteString("🔐 **Confirmation required**")
	// Lead with the plain-language description when the tool supplies one
	// (run_js); otherwise fall back to the permission name. Not every tool
	// carries a description.
	if description != "" {
		sb.WriteString("\n")
		sb.WriteString(description)
	} else if permission != "" {
		sb.WriteString("\nPermission: `")
		sb.WriteString(permission)
		sb.WriteString("`")
	}
	if code != "" {
		sb.WriteString("\n")
		sb.WriteString(codeFence(code))
	}
	return sb.String()
}

// approvalKeyboard builds the two-button inline keyboard for a suspended run.
// callback_data encodes the runID so stale taps can be detected server-side.
func approvalKeyboard(runID string) map[string]any {
	return map[string]any{
		"inline_keyboard": [][]map[string]any{
			{
				{"text": "✅ Approve", "callback_data": "approve:" + runID},
				{"text": "❌ Deny", "callback_data": "deny:" + runID},
			},
		},
	}
}

// cancelKeyboard builds the single-button keyboard attached to the
// "Still working…" message posted after CancelButtonAfter elapses.
func cancelKeyboard(runID string) map[string]any {
	return map[string]any{
		"inline_keyboard": [][]map[string]any{
			{{"text": "🛑 Stop", "callback_data": "cancel:" + runID}},
		},
	}
}

// scheduleCancelButton waits CancelButtonAfter from run start. If the run
// is still streaming when the timer fires, it posts a "Still working…"
// message with a cancel button and waits for the run to end so it can
// delete the message. If the run finishes first, the goroutine just exits.
func (d *TelegramDriver) scheduleCancelButton(ctx context.Context, token string, chatID int64, runID string, runEndedCh <-chan struct{}) {
	select {
	case <-runEndedCh:
		return
	case <-ctx.Done():
		return
	case <-time.After(CancelButtonAfter):
	}

	msgID, err := d.sendMessageWithButtons(ctx, token, chatID, "⏳ Still working…", cancelKeyboard(runID))
	if err != nil {
		return
	}

	<-runEndedCh
	delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = d.deleteMessage(delCtx, token, chatID, msgID)
}

// formatToolResult formats a tool result as Rich Markdown.
// output is the tool's string output (already unwrapped from tool.Result in prompt.go).
func formatToolResult(toolName, output, toolError string) string {
	if toolError != "" {
		return "✗ **" + toolName + "**: " + toolError
	}
	if output == "" {
		return "✓ **" + toolName + "**"
	}
	if len(output) > 500 {
		output = output[:500] + "…"
	}
	return "✓ **" + toolName + "**\n" + codeFence(output)
}

// GetMe calls the Telegram getMe API and returns the bot username.
func (d *TelegramDriver) GetMe(ctx context.Context, token string) (string, error) {
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getMe", nil, &result); err != nil {
		return "", err
	}
	if !result.OK {
		return "", fmt.Errorf("telegram getMe: not ok")
	}
	return result.Result.Username, nil
}

// GetMeFull calls getMe and returns the bot's username, stable user id, and
// can_manage_bots capability. Used where airlock needs the bot identity (to
// dedupe one-listener-per-bot) and the manager capability (to gate the
// is_manager behavior), not just the username.
func (d *TelegramDriver) GetMeFull(ctx context.Context, token string) (username string, botUserID int64, canManageBots bool, err error) {
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			ID            int64  `json:"id"`
			Username      string `json:"username"`
			CanManageBots bool   `json:"can_manage_bots"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getMe", nil, &result); err != nil {
		return "", 0, false, err
	}
	if !result.OK {
		return "", 0, false, fmt.Errorf("telegram getMe: not ok")
	}
	return result.Result.Username, result.Result.ID, result.Result.CanManageBots, nil
}

// GetManagedBotToken fetches the bot token for a managed bot the manager bot
// just created. Bot API getManagedBotToken takes the new bot's user_id and
// returns the token directly under `result` (managerToken authenticates the
// call — it must have can_manage_bots).
func (d *TelegramDriver) GetManagedBotToken(ctx context.Context, managerToken string, botUserID int64) (string, error) {
	var result struct {
		OK     bool   `json:"ok"`
		Result string `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, managerToken, "getManagedBotToken", map[string]any{"user_id": botUserID}, &result); err != nil {
		return "", err
	}
	if !result.OK || result.Result == "" {
		return "", fmt.Errorf("telegram getManagedBotToken: no token")
	}
	return result.Result, nil
}

// SetMenuButton configures the bot's default chat menu button to launch
// a Telegram Web App at the given URL. The button is persistent — it
// shows for every private chat the bot is in, opens the URL in
// Telegram's in-app browser, and exposes initData to the page so airlock
// can authenticate the user automatically.
//
// Passing url=="" clears the bot back to Telegram's default menu (the
// commands list). Called once on bridge activation / token refresh; not
// idempotent at the Telegram side (each call re-publishes the button)
// but cheap and safe to call repeatedly.
func (d *TelegramDriver) SetMenuButton(ctx context.Context, token, url string) error {
	var menuButton map[string]any
	if url == "" {
		menuButton = map[string]any{"type": "default"}
	} else {
		menuButton = map[string]any{
			"type": "web_app",
			"text": "Open",
			"web_app": map[string]any{
				"url": url,
			},
		}
	}
	body := map[string]any{"menu_button": menuButton}
	var result struct {
		OK bool `json:"ok"`
	}
	if err := d.callTelegramJSON(ctx, token, "setChatMenuButton", body, &result); err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("telegram setChatMenuButton: not ok")
	}
	return nil
}

// TelegramChatInfo holds the subset of getChat fields we expose.
type TelegramChatInfo struct {
	Username  string
	FirstName string
	LastName  string
}

// GetChat calls the Telegram getChat API for a private chat. Because private
// chat IDs equal the user ID, this resolves a telegram user's public username
// and display name as long as that user has DM'd the bot.
func (d *TelegramDriver) GetChat(ctx context.Context, token, chatID string) (TelegramChatInfo, error) {
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			Username  string `json:"username"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getChat", map[string]string{"chat_id": chatID}, &result); err != nil {
		return TelegramChatInfo{}, err
	}
	if !result.OK {
		return TelegramChatInfo{}, fmt.Errorf("telegram getChat: not ok")
	}
	return TelegramChatInfo{
		Username:  result.Result.Username,
		FirstName: result.Result.FirstName,
		LastName:  result.Result.LastName,
	}, nil
}

// SendMessage sends a text message to a Telegram chat.
func (d *TelegramDriver) SendMessage(ctx context.Context, token string, chatID int64, text string) error {
	_, err := d.sendMessage(ctx, token, chatID, text)
	return err
}

// deleteMessage removes a previously sent message. Used by SendStream to
// clean up the "Still working…" cancel-button message once the run ends.
// Errors are logged at debug — best-effort cleanup, not critical.
func (d *TelegramDriver) deleteMessage(ctx context.Context, token string, chatID, messageID int64) error {
	return d.callTelegram(ctx, token, "deleteMessage", map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
	})
}

// RemoveButtons strips the inline keyboard from a previously sent
// message via editMessageReplyMarkup. The message text is left intact
// so the conversation history still shows what was being confirmed.
func (d *TelegramDriver) RemoveButtons(ctx context.Context, br dbq.Bridge, externalID, messageID string) error {
	chatID, err := strconv.ParseInt(externalID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid chat ID %q: %w", externalID, err)
	}
	msgID, err := strconv.ParseInt(messageID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid message ID %q: %w", messageID, err)
	}
	// Empty reply_markup clears the keyboard; omitting the field would
	// leave the existing keyboard in place.
	return d.callTelegram(ctx, br.BotTokenRef, "editMessageReplyMarkup", map[string]any{
		"chat_id":      chatID,
		"message_id":   msgID,
		"reply_markup": map[string]any{"inline_keyboard": [][]map[string]any{}},
	})
}

// sendChatAction calls sendChatAction — the one-shot "typing…" indicator.
// Telegram clears it automatically after ~5 seconds or on the next outgoing
// message, so callers that want a sustained indicator must re-send it.
func (d *TelegramDriver) sendChatAction(ctx context.Context, token string, chatID int64, action string) error {
	return d.callTelegram(ctx, token, "sendChatAction", map[string]any{
		"chat_id": chatID,
		"action":  action,
	})
}

// keepTyping fires a "typing…" action immediately and then every 4 seconds
// in the background until the returned stop function is called or ctx is
// cancelled. Returns a stop closure that is safe to call multiple times.
func (d *TelegramDriver) keepTyping(ctx context.Context, token string, chatID int64) func() {
	_ = d.sendChatAction(ctx, token, chatID, "typing")

	tickCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(4 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-tickCtx.Done():
				return
			case <-t.C:
				_ = d.sendChatAction(tickCtx, token, chatID, "typing")
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// SendParts sends display parts to a Telegram chat.
// Renders each part appropriately: text → sendMessage, image → sendPhoto, file → sendDocument.
func (d *TelegramDriver) SendParts(ctx context.Context, token string, chatID int64, parts []agentsdk.DisplayPart) error {
	var textBuf strings.Builder
	var lastErr error

	flush := func() {
		if textBuf.Len() > 0 {
			// Send as a Rich Message so markdown (tables, **bold**, etc.)
			// renders natively. Mirrors the SendStream path. Media parts below
			// still upload via sendPhoto/sendDocument.
			_, _ = d.sendRichMessage(ctx, token, chatID, textBuf.String(), nil)
			textBuf.Reset()
		}
	}

	for _, p := range parts {
		switch p.Type {
		case "text":
			if textBuf.Len() > 0 {
				textBuf.WriteString("\n")
			}
			textBuf.WriteString(p.Text)
		case "image":
			flush()
			caption := p.Text
			if caption == "" {
				caption = p.Alt
			}
			if len(p.Data) > 0 {
				if err := d.sendPhotoUpload(ctx, token, chatID, p.Data, p.Filename, caption); err != nil {
					lastErr = err
				}
			} else if url := firstNonEmpty(p.URL, p.Source); url != "" {
				if err := d.sendPhoto(ctx, token, chatID, url, caption); err != nil {
					lastErr = err
				}
			}
		case "file", "audio", "video":
			flush()
			if len(p.Data) > 0 {
				if err := d.sendDocumentUpload(ctx, token, chatID, p.Data, p.Filename); err != nil {
					lastErr = err
				}
			} else if url := firstNonEmpty(p.URL, p.Source); url != "" {
				if err := d.sendDocument(ctx, token, chatID, url, p.Filename); err != nil {
					lastErr = err
				}
			}
		}
	}
	flush()
	return lastErr
}

// --- Telegram API helpers ---

func (d *TelegramDriver) getUpdates(ctx context.Context, token string, offset int64, timeout int) ([]telegramUpdate, error) {
	body := map[string]any{
		"offset":  offset,
		"timeout": timeout,
	}
	var result struct {
		OK     bool             `json:"ok"`
		Result []telegramUpdate `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getUpdates", body, &result); err != nil {
		return nil, err
	}
	return result.Result, nil
}

// sendMessageDraft streams a partial message to the user (Bot API 9.3+).
func (d *TelegramDriver) sendMessageDraft(ctx context.Context, token string, chatID int64, draftID, text string) error {
	body := map[string]any{
		"business_connection_id": "", // not used, but required field structure
		"chat_id":                chatID,
		"text":                   text,
		"draft_id":               draftID,
	}
	return d.callTelegram(ctx, token, "sendMessageDraft", body)
}

// isParseError returns true if a Telegram API error is a 400 Bad Request
// caused by entity/parse failures — the signal to retry without parse_mode.
func isParseError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "status 400") &&
		(strings.Contains(s, "can't parse entities") ||
			strings.Contains(s, "can't find end of the entity") ||
			strings.Contains(s, "unsupported start tag") ||
			strings.Contains(s, "unclosed") ||
			strings.Contains(s, "Unsupported"))
}

// sendMessage sends an HTML-formatted message. On parse failure, retries
// as plain text so the user at least sees the content. Errors are logged.
func (d *TelegramDriver) sendMessage(ctx context.Context, token string, chatID int64, text string) (int64, error) {
	return d.sendMessageInner(ctx, token, chatID, text, nil)
}

// sendMessageWithButtons sends an HTML message with an attached inline keyboard.
func (d *TelegramDriver) sendMessageWithButtons(ctx context.Context, token string, chatID int64, text string, keyboard map[string]any) (int64, error) {
	return d.sendMessageInner(ctx, token, chatID, text, keyboard)
}

// sendRichMessage delivers agent content as a Bot API 10.1 Rich Message. The
// markdown is passed through verbatim — Telegram's rich-markdown parser renders
// tables, headings, lists, block quotes, and fenced code that the legacy HTML
// subset (sendMessage) can't. reply_markup is supported, so inline keyboards
// (approval/cancel) ride along. There is no HTML fallback: rich markdown is
// lenient, and a failure is logged like any other send error. The rich text
// limit is 32768 chars, so the 4096-char chunking sendMessage needs doesn't
// apply here.
func (d *TelegramDriver) sendRichMessage(ctx context.Context, token string, chatID int64, md string, keyboard map[string]any) (int64, error) {
	if strings.TrimSpace(md) == "" {
		return 0, nil
	}
	body := map[string]any{
		"chat_id":      chatID,
		"rich_message": map[string]any{"markdown": md},
	}
	if keyboard != nil {
		body["reply_markup"] = keyboard
	}
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "sendRichMessage", body, &result); err != nil {
		d.logger.Error("telegram sendRichMessage failed",
			zap.Int64("chatID", chatID),
			zap.Error(err),
			zap.String("preview", preview(md, 200)),
		)
		return 0, err
	}
	return result.Result.MessageID, nil
}

// sendMessageInner splits text into chunks within Telegram's per-message
// length limit and sends each. A keyboard is attached to the final chunk
// only. Returns the last chunk's message ID — the one callers edit or
// remove buttons from. Blank text sends nothing.
func (d *TelegramDriver) sendMessageInner(ctx context.Context, token string, chatID int64, text string, keyboard map[string]any) (int64, error) {
	chunks := splitForTelegram(text)
	if len(chunks) == 0 {
		return 0, nil
	}
	var lastID int64
	for i, chunk := range chunks {
		var kb map[string]any
		if i == len(chunks)-1 {
			kb = keyboard
		}
		id, err := d.sendOne(ctx, token, chatID, chunk, kb)
		if err != nil {
			return lastID, err
		}
		lastID = id
	}
	return lastID, nil
}

// sendOne sends a single message already within Telegram's length limit.
// HTML-first; on a parse failure retries the same text as plain text so
// the user still sees the content. Errors are logged.
func (d *TelegramDriver) sendOne(ctx context.Context, token string, chatID int64, text string, keyboard map[string]any) (int64, error) {
	body := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if keyboard != nil {
		body["reply_markup"] = keyboard
	}
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
	}

	err := d.callTelegramJSON(ctx, token, "sendMessage", body, &result)
	if err == nil {
		return result.Result.MessageID, nil
	}

	// If HTML parsing failed, retry as plain text so the user still sees
	// the content. Log both the original failure and the retry outcome.
	if isParseError(err) {
		d.logger.Warn("telegram sendMessage HTML parse failed — retrying as plain text",
			zap.Int64("chatID", chatID),
			zap.Error(err),
			zap.String("preview", preview(text, 200)),
		)
		delete(body, "parse_mode")
		if err2 := d.callTelegramJSON(ctx, token, "sendMessage", body, &result); err2 != nil {
			d.logger.Error("telegram sendMessage plain-text fallback failed",
				zap.Int64("chatID", chatID),
				zap.Error(err2),
			)
			return 0, fmt.Errorf("plain-text fallback failed after HTML parse error: %w", err2)
		}
		return result.Result.MessageID, nil
	}

	// Non-parse error (network, 429 rate-limit, 401 auth, etc.) — log and propagate.
	d.logger.Error("telegram sendMessage failed",
		zap.Int64("chatID", chatID),
		zap.Error(err),
		zap.String("preview", preview(text, 200)),
	)
	return 0, err
}

// preview truncates a string for log lines.
func preview(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// AnswerCallbackQuery clears the loading spinner on a tapped inline-keyboard
// button. If text is non-empty, Telegram shows it as a transient toast.
func (d *TelegramDriver) AnswerCallbackQuery(ctx context.Context, token, callbackID, text string) error {
	body := map[string]any{"callback_query_id": callbackID}
	if text != "" {
		body["text"] = text
	}
	return d.callTelegram(ctx, token, "answerCallbackQuery", body)
}

func (d *TelegramDriver) sendPhoto(ctx context.Context, token string, chatID int64, photoURL, caption string) error {
	body := map[string]any{
		"chat_id": chatID,
		"photo":   photoURL,
	}
	if caption != "" {
		body["caption"] = markdownToTelegramHTML(caption)
		body["parse_mode"] = "HTML"
	}
	return d.callTelegram(ctx, token, "sendPhoto", body)
}

func (d *TelegramDriver) sendDocument(ctx context.Context, token string, chatID int64, documentURL, filename string) error {
	body := map[string]any{
		"chat_id":  chatID,
		"document": documentURL,
	}
	if filename != "" {
		body["caption"] = filename
	}
	return d.callTelegram(ctx, token, "sendDocument", body)
}

// sendPhotoUpload sends a photo as multipart/form-data upload (for local bytes).
func (d *TelegramDriver) sendPhotoUpload(ctx context.Context, token string, chatID int64, data []byte, filename, caption string) error {
	if filename == "" {
		filename = "photo.jpg"
	}
	return d.sendMultipart(ctx, token, "sendPhoto", chatID, "photo", data, filename, caption)
}

// sendDocumentUpload sends a document as multipart/form-data upload (for local bytes).
func (d *TelegramDriver) sendDocumentUpload(ctx context.Context, token string, chatID int64, data []byte, filename string) error {
	if filename == "" {
		filename = "file"
	}
	return d.sendMultipart(ctx, token, "sendDocument", chatID, "document", data, filename, "")
}

// sendMultipart sends a file to Telegram via multipart/form-data.
func (d *TelegramDriver) sendMultipart(ctx context.Context, token, method string, chatID int64, fieldName string, data []byte, filename, caption string) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	w.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	if caption != "" {
		w.WriteField("caption", markdownToTelegramHTML(caption))
		w.WriteField("parse_mode", "HTML")
	}
	part, err := w.CreateFormFile(fieldName, filename)
	if err != nil {
		return err
	}
	part.Write(data)
	w.Close()

	base := d.baseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	url := fmt.Sprintf("%s/bot%s/%s", base, token, method)

	req, err := http.NewRequestWithContext(ctx, "POST", url, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram %s: status %d: %s", method, resp.StatusCode, string(body))
	}
	return nil
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// downloadFile fetches a file from Telegram by file_id.
// Uses getFile to get the file path, then downloads from the file URL.
func (d *TelegramDriver) downloadFile(ctx context.Context, token, fileID string) ([]byte, error) {
	var result struct {
		OK     bool `json:"ok"`
		Result struct {
			FilePath string `json:"file_path"`
		} `json:"result"`
	}
	if err := d.callTelegramJSON(ctx, token, "getFile", map[string]string{"file_id": fileID}, &result); err != nil {
		return nil, fmt.Errorf("getFile: %w", err)
	}
	if result.Result.FilePath == "" {
		return nil, fmt.Errorf("getFile: empty file_path")
	}

	base := d.baseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	fileURL := fmt.Sprintf("%s/file/bot%s/%s", base, token, result.Result.FilePath)

	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download file: status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (d *TelegramDriver) callTelegram(ctx context.Context, token, method string, body any) error {
	return d.callTelegramJSON(ctx, token, method, body, nil)
}

func (d *TelegramDriver) callTelegramJSON(ctx context.Context, token, method string, body any, result any) error {
	base := d.baseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	url := fmt.Sprintf("%s/bot%s/%s", base, token, method)

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram %s: status %d: %s", method, resp.StatusCode, string(respBody))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// --- Telegram types ---

type telegramConfig struct {
	Offset int64 `json:"offset"`
}

type telegramUpdate struct {
	UpdateID      int64                  `json:"update_id"`
	Message       *telegramMessage       `json:"message"`
	CallbackQuery *telegramCallbackQuery `json:"callback_query"`
}

type telegramCallbackQuery struct {
	ID      string           `json:"id"`
	From    telegramUser     `json:"from"`
	Message *telegramMessage `json:"message"` // the message the button was attached to
	Data    string           `json:"data"`
}

type telegramMessage struct {
	MessageID      int64                `json:"message_id"`
	Date           int64                `json:"date"` // unix seconds
	From           telegramUser         `json:"from"`
	Chat           telegramChat         `json:"chat"`
	Text           string               `json:"text"`
	Caption        string               `json:"caption"`
	Photo          []telegramPhotoSize  `json:"photo"`
	Document       *telegramDocument    `json:"document"`
	Voice          *telegramVoice       `json:"voice"`
	Audio          *telegramAudio       `json:"audio"`
	VideoNote      *telegramVideoNote   `json:"video_note"`
	Video          *telegramVideo       `json:"video"`
	ReplyToMessage *telegramMessage     `json:"reply_to_message"`
	ForwardOrigin  *telegramForwardInfo `json:"forward_origin"`
	// ManagedBotCreated is the Bot API service message delivered to a
	// manager bot when a user finishes creating a bot via the deep-link
	// flow. Only manager bridges act on it (see HandleEvent).
	ManagedBotCreated *telegramManagedBotCreated `json:"managed_bot_created"`
}

// telegramManagedBotCreated — the `managed_bot_created` service message.
// Only the bot is included; its token is fetched separately via
// getManagedBotToken{user_id: bot.id}.
type telegramManagedBotCreated struct {
	Bot struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"bot"`
}

// telegramForwardInfo is the modern (Bot API 7.0+) forward_origin field.
// We only read the human-readable bits we need to render a forward
// reference; the legacy forward_from / forward_from_chat fields are
// ignored — Telegram has been emitting forward_origin alongside the
// legacy fields for years.
// telegramReferenced extracts a normalized reference (reply target or
// forward source) from an inbound message, if any. forward_origin
// (post-Bot-API-7.0) is preferred over reply_to_message — a forwarded
// message that's also a reply is rare in practice and we want the
// forward semantics in that case.
func telegramReferenced(m *telegramMessage) *BridgeReferencedMessage {
	if m == nil {
		return nil
	}
	if m.ForwardOrigin != nil {
		fo := m.ForwardOrigin
		var name string
		switch {
		case fo.SenderUser != nil:
			name = fo.SenderUser.FirstName
		case fo.SenderUserName != "":
			name = fo.SenderUserName
		case fo.AuthorSignature != "":
			name = fo.AuthorSignature
		}
		text := m.Text
		if text == "" {
			text = m.Caption
		}
		return &BridgeReferencedMessage{
			Kind:       BridgeReferenceForward,
			SenderName: name,
			Text:       text,
			AuthoredAt: time.Unix(fo.Date, 0),
		}
	}
	if m.ReplyToMessage != nil {
		ref := m.ReplyToMessage
		text := ref.Text
		if text == "" {
			text = ref.Caption
		}
		return &BridgeReferencedMessage{
			Kind:       BridgeReferenceReply,
			SenderName: ref.From.FirstName,
			Text:       text,
			AuthoredAt: time.Unix(ref.Date, 0),
		}
	}
	return nil
}

type telegramForwardInfo struct {
	Type            string        `json:"type"` // "user" | "hidden_user" | "chat" | "channel"
	Date            int64         `json:"date"`
	SenderUser      *telegramUser `json:"sender_user"`
	SenderUserName  string        `json:"sender_user_name"` // used when Type == "hidden_user"
	SenderChat      *telegramChat `json:"sender_chat"`
	AuthorSignature string        `json:"author_signature"`
}

type telegramPhotoSize struct {
	FileID   string `json:"file_id"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	FileSize int64  `json:"file_size"`
}

type telegramDocument struct {
	FileID   string `json:"file_id"`
	FileName string `json:"file_name"`
	MimeType string `json:"mime_type"`
	FileSize int64  `json:"file_size"`
}

type telegramVoice struct {
	FileID   string `json:"file_id"`
	Duration int    `json:"duration"`
	MimeType string `json:"mime_type"`
	FileSize int64  `json:"file_size"`
}

type telegramAudio struct {
	FileID    string `json:"file_id"`
	Duration  int    `json:"duration"`
	MimeType  string `json:"mime_type"`
	FileSize  int64  `json:"file_size"`
	FileName  string `json:"file_name"`
	Title     string `json:"title"`
	Performer string `json:"performer"`
}

type telegramVideoNote struct {
	FileID   string `json:"file_id"`
	Duration int    `json:"duration"`
	FileSize int64  `json:"file_size"`
}

type telegramVideo struct {
	FileID   string `json:"file_id"`
	Duration int    `json:"duration"`
	MimeType string `json:"mime_type"`
	FileSize int64  `json:"file_size"`
	FileName string `json:"file_name"`
}

type telegramUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
}

type telegramChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

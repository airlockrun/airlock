package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/coder/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// DiscordDriver speaks the Discord Gateway WebSocket for inbound events
// and the v10 REST API for outbound message delivery. Single-replica
// only today: the Gateway connection holds session state and only one
// process can identify per token, so multi-replica needs a per-bridge
// advisory lock added later.
type DiscordDriver struct {
	httpClient *http.Client
	apiBase    string // default "https://discord.com/api/v10", override for testing
	logger     *zap.Logger

	mu      sync.Mutex
	bridges map[uuid.UUID]*discordConn // owned WS goroutines, keyed by bridge.ID
}

// discordConn is the per-bridge state the WS goroutine maintains. The
// channel is the pipe into the Poll loop; cancel tears the goroutine
// down on Teardown / RemoveBridge.
type discordConn struct {
	cancel        context.CancelFunc
	events        chan BridgeEvent
	mu            sync.Mutex
	sessionID     string
	lastSeq       int64
	resumeURL     string // "Resume Gateway URL" handed back in READY
	applicationID string
	botUserID     string
	botUsername   string
}

// Discord intent flags for DM-only operation. MESSAGE_CONTENT is a
// privileged intent — the operator must enable it in the Discord
// developer portal under Bot → Privileged Gateway Intents. Up to 100
// servers it's free; beyond that Discord requires verification.
const (
	discordIntentDirectMessages = 1 << 12 // 4096 — DM messages
	discordIntentMessageContent = 1 << 15 // 32768 — privileged: read message content
	discordDMIntents            = discordIntentDirectMessages | discordIntentMessageContent
)

// discordPrivilegedIntents lists the privileged intents we request, with
// the human-friendly toggle names from the Discord developer portal.
// Used when Discord rejects IDENTIFY with close 4014 so the operator
// knows exactly which checkboxes to flip.
var discordPrivilegedIntents = []struct {
	flag int
	name string // matches the label in dev portal → Bot → Privileged Gateway Intents
}{
	{discordIntentMessageContent, "MESSAGE CONTENT INTENT"},
}

// discordCloseFatal returns a non-empty hint message when the close code
// indicates a config error retrying won't fix.
func discordCloseFatal(code int) string {
	switch code {
	case 4004:
		return "authentication failed — bot token rejected"
	case 4013:
		return "invalid intent value sent in IDENTIFY"
	case 4014:
		var enabled []string
		for _, in := range discordPrivilegedIntents {
			if discordDMIntents&in.flag != 0 {
				enabled = append(enabled, in.name)
			}
		}
		return "disallowed intent(s) — enable in Discord developer portal under Bot → Privileged Gateway Intents: " + strings.Join(enabled, ", ")
	}
	return ""
}

// Gateway opcodes (https://discord.com/developers/docs/topics/opcodes-and-status-codes).
const (
	dOpDispatch       = 0
	dOpHeartbeat      = 1
	dOpIdentify       = 2
	dOpResume         = 6
	dOpReconnect      = 7
	dOpInvalidSession = 9
	dOpHello          = 10
	dOpHeartbeatACK   = 11

	// Interaction types from INTERACTION_CREATE.d.type.
	dInteractionTypeApplicationCommand = 2
	dInteractionTypeMessageComponent   = 3

	// Interaction callback response types.
	dInteractionRespondMessage         = 4 // CHANNEL_MESSAGE_WITH_SOURCE
	dInteractionRespondDeferredMessage = 5 // DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE
	dInteractionRespondDeferredUpdate  = 6 // DEFERRED_UPDATE_MESSAGE (component)

	// Message flag — only the invoking user can see the response.
	dMessageFlagEphemeral = 1 << 6
)

// NewDiscordDriver creates a DiscordDriver. logger surfaces gateway and
// REST errors. Pass zap.NewNop() in tests.
func NewDiscordDriver(logger *zap.Logger) *DiscordDriver {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &DiscordDriver{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
		bridges:    make(map[uuid.UUID]*discordConn),
	}
}

// NewDiscordDriverWithBase creates a DiscordDriver pointed at an
// alternate REST base URL. The Gateway URL is fetched via GET /gateway/bot
// and inherits the same prefix for tests.
func NewDiscordDriverWithBase(apiBase string, client *http.Client) *DiscordDriver {
	return &DiscordDriver{httpClient: client, apiBase: apiBase, logger: zap.NewNop(), bridges: make(map[uuid.UUID]*discordConn)}
}

// --- BridgeDriver interface ---

func (d *DiscordDriver) Init(ctx context.Context, br *dbq.Bridge) error {
	// First-time setup. We persist the application_id discovered from
	// GET /users/@me so RegisterCommands / interaction-respond paths
	// don't need a fresh round-trip every startup.
	info, err := d.fetchBotInfo(ctx, br.BotTokenRef)
	if err != nil {
		return fmt.Errorf("discord init: %w", err)
	}
	cfg := discordBridgeConfig{ApplicationID: info.ApplicationID}
	br.Config = mustJSON(cfg)
	return nil
}

func (d *DiscordDriver) Activate(ctx context.Context, br dbq.Bridge) error {
	d.mu.Lock()
	if existing, ok := d.bridges[pgUUID(br.ID)]; ok {
		// AddBridge or duplicate Activate — tear down the prior
		// connection first so we never have two WS sessions racing
		// the same token.
		existing.cancel()
		delete(d.bridges, pgUUID(br.ID))
	}
	d.mu.Unlock()

	var cfg discordBridgeConfig
	_ = json.Unmarshal(br.Config, &cfg)

	connCtx, cancel := context.WithCancel(context.Background())
	conn := &discordConn{
		cancel:        cancel,
		events:        make(chan BridgeEvent, 256),
		applicationID: cfg.ApplicationID,
	}
	d.mu.Lock()
	d.bridges[pgUUID(br.ID)] = conn
	d.mu.Unlock()

	token := br.BotTokenRef
	go d.runGateway(connCtx, br, token, conn)
	return nil
}

func (d *DiscordDriver) Teardown(_ context.Context, br dbq.Bridge) error {
	d.mu.Lock()
	conn, ok := d.bridges[pgUUID(br.ID)]
	delete(d.bridges, pgUUID(br.ID))
	d.mu.Unlock()
	if ok {
		conn.cancel()
	}
	return nil
}

// DefaultEcho mirrors Telegram: tool-call/tool-result bubbles are off by
// default. Each tool call would render as a separate message and a
// chatty agent quickly fills the DM.
func (d *DiscordDriver) DefaultEcho() bool { return false }

// Poll blocks until the gateway goroutine has buffered events or the
// timeout fires. The driver handles its own reconnect, so Poll never
// returns errors — a dead WS just yields no events until reconnect.
func (d *DiscordDriver) Poll(ctx context.Context, br *dbq.Bridge) ([]BridgeEvent, error) {
	d.mu.Lock()
	conn, ok := d.bridges[pgUUID(br.ID)]
	d.mu.Unlock()
	if !ok {
		// Activate hasn't run yet (or Teardown beat us). Sleep a beat
		// so the BridgeManager poller doesn't spin.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return nil, nil
		}
	}

	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	var events []BridgeEvent
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timeout.C:
		return nil, nil
	case ev := <-conn.events:
		events = append(events, ev)
	}
	// Drain any buffered events before returning so we can batch.
	for {
		select {
		case ev := <-conn.events:
			events = append(events, ev)
		default:
			return events, nil
		}
	}
}

// --- CommandRegistrar ---

// RegisterCommands bulk-overwrites the global slash commands for this
// bot's application. Global commands take up to ~1 hour to propagate
// across Discord's edge — first-time install is fine, name changes lag.
func (d *DiscordDriver) RegisterCommands(ctx context.Context, br dbq.Bridge, cmds []SlashCommand) error {
	var cfg discordBridgeConfig
	_ = json.Unmarshal(br.Config, &cfg)
	if cfg.ApplicationID == "" {
		return fmt.Errorf("discord: applicationID missing from bridge config")
	}

	body := make([]map[string]any, len(cmds))
	for i, c := range cmds {
		body[i] = map[string]any{
			"name":        c.Name,
			"description": c.Description,
			"type":        1, // CHAT_INPUT
			// Allow in DMs (default), guild text channels.
			"contexts": []int{0, 1, 2},
		}
	}
	url := d.api() + "/applications/" + cfg.ApplicationID + "/commands"
	return d.callDiscord(ctx, br.BotTokenRef, http.MethodPut, url, body, nil)
}

// --- SendStream ---

func (d *DiscordDriver) SendStream(ctx context.Context, br dbq.Bridge, externalID string, echo bool, events <-chan ResponseEvent) (string, error) {
	token := br.BotTokenRef
	channelID := externalID

	// Discord doesn't expose a "typing…" indicator that survives more
	// than ~10s, but POST /channels/{id}/typing keeps it alive on a
	// loop. Mirrors Telegram's keepTyping.
	stopTyping := d.keepTyping(ctx, token, channelID)
	defer stopTyping()

	var sb strings.Builder
	flushText := func() {
		text := sb.String()
		if text != "" {
			_, _ = d.sendMessage(ctx, token, channelID, text, nil)
			sb.Reset()
		}
	}

	for ev := range events {
		switch ev.Type {
		case "text-delta":
			sb.WriteString(ev.Text)

		case "tool-call":
			flushText()
			if echo {
				_, _ = d.sendMessage(ctx, token, channelID, formatDiscordToolCall(ev.ToolName, ev.ToolInput), nil)
			}

		case "tool-result", "tool-error":
			isError := ev.Type == "tool-error" || ev.ToolError != ""
			if !echo && !isError {
				continue
			}
			_, _ = d.sendMessage(ctx, token, channelID, formatDiscordToolResult(ev.ToolName, ev.ToolOutput, ev.ToolError), nil)

		case "confirmation_required":
			flushText()
			text := formatDiscordConfirmation(ev.Permission, ev.Patterns, ev.Code)
			components := discordApprovalButtons(ev.RunID)
			_, _ = d.sendMessage(ctx, token, channelID, text, components)

		case "info":
			flushText()
			if ev.Text != "" {
				_, _ = d.sendMessage(ctx, token, channelID, ev.Text, nil)
			}
		}
	}

	flushText()
	return sb.String(), nil
}

// --- SendParts (used by direct delivery from the agent) ---

// SendParts sends display parts to a Discord channel — text, images, files.
func (d *DiscordDriver) SendParts(ctx context.Context, token, channelID string, parts []agentsdk.DisplayPart) error {
	var textBuf strings.Builder
	var lastErr error

	flush := func() {
		if textBuf.Len() > 0 {
			_, _ = d.sendMessage(ctx, token, channelID, textBuf.String(), nil)
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
		case "image", "file", "audio", "video":
			flush()
			if len(p.Data) > 0 {
				name := p.Filename
				if name == "" {
					name = "file"
				}
				if err := d.sendFile(ctx, token, channelID, p.Data, name, p.Text); err != nil {
					lastErr = err
				}
			} else if url := firstNonEmpty(p.URL, p.Source); url != "" {
				caption := p.Text
				if caption == "" {
					caption = url
				} else {
					caption = caption + "\n" + url
				}
				_, _ = d.sendMessage(ctx, token, channelID, caption, nil)
			}
		}
	}
	flush()
	return lastErr
}

// --- Gateway (WS) ---

// runGateway is the long-lived connection loop. On any disconnect it
// backs off and either resumes (when session_id + last_seq are known
// and the close code permits) or starts a fresh IDENTIFY. ctx cancel
// terminates the loop; everything else is recoverable.
func (d *DiscordDriver) runGateway(ctx context.Context, br dbq.Bridge, token string, conn *discordConn) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := d.gatewaySession(ctx, br, token, conn)
		if err != nil && ctx.Err() == nil {
			// Some close codes are config errors — retrying just spams
			// Discord with a known-bad IDENTIFY. Log a clear hint and
			// stop. Operator restarts airlock after fixing the dev
			// portal toggle / token.
			closeCode := websocket.CloseStatus(err)
			if hint := discordCloseFatal(int(closeCode)); hint != "" {
				d.logger.Error("discord gateway: fatal config error, not reconnecting",
					zap.String("bridge", br.Name),
					zap.Int("close_code", int(closeCode)),
					zap.String("hint", hint),
				)
				return
			}
			d.logger.Warn("discord gateway disconnected",
				zap.String("bridge", br.Name),
				zap.Error(err),
			)
			// Cap backoff at 60s. Discord's docs warn against tight
			// reconnect loops — they'll IP-ban repeat offenders.
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
			continue
		}
		// Clean shutdown.
		if ctx.Err() != nil {
			return
		}
		// Server-initiated reconnect (op 7 or close 4xxx with resume
		// allowed). Reset backoff — these are normal.
		backoff = time.Second
	}
}

// gatewaySession runs one WS session — connect, hello, identify-or-resume,
// pump events, return when the connection ends. Returns nil on a clean
// reconnect signal (so the outer loop resets backoff) and an error for
// network / protocol failures.
func (d *DiscordDriver) gatewaySession(ctx context.Context, br dbq.Bridge, token string, conn *discordConn) error {
	gwURL, err := d.gatewayURL(ctx, token, conn)
	if err != nil {
		return fmt.Errorf("fetch gateway url: %w", err)
	}

	wsCtx, wsCancel := context.WithCancel(ctx)
	defer wsCancel()

	c, _, err := websocket.Dial(wsCtx, gwURL+"?v=10&encoding=json", nil)
	if err != nil {
		return fmt.Errorf("dial gateway: %w", err)
	}
	// Discord can send messages up to 4 MiB on the gateway.
	c.SetReadLimit(1 << 22)
	defer c.CloseNow()

	// First frame must be HELLO.
	hello, err := readGatewayPayload(wsCtx, c)
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	if hello.Op != dOpHello {
		return fmt.Errorf("expected HELLO, got op %d", hello.Op)
	}
	var helloD struct {
		HeartbeatInterval int64 `json:"heartbeat_interval"`
	}
	if err := json.Unmarshal(hello.D, &helloD); err != nil {
		return fmt.Errorf("parse hello: %w", err)
	}

	// Heartbeat pump. Discord wants the first heartbeat jittered by
	// `heartbeat_interval * jitter` (jitter ∈ [0,1]) per spec; failure
	// to do so won't disconnect us but it's polite.
	heartbeatErr := make(chan error, 1)
	gotAck := make(chan struct{}, 1)
	go d.runHeartbeat(wsCtx, c, conn, time.Duration(helloD.HeartbeatInterval)*time.Millisecond, gotAck, heartbeatErr)

	// IDENTIFY (fresh session) or RESUME (existing session_id).
	conn.mu.Lock()
	resumeOK := conn.sessionID != "" && conn.resumeURL != ""
	sessionID, lastSeq := conn.sessionID, conn.lastSeq
	conn.mu.Unlock()

	if resumeOK {
		if err := writeGatewayPayload(wsCtx, c, map[string]any{
			"op": dOpResume,
			"d": map[string]any{
				"token":      token,
				"session_id": sessionID,
				"seq":        lastSeq,
			},
		}); err != nil {
			return fmt.Errorf("send resume: %w", err)
		}
	} else {
		if err := writeGatewayPayload(wsCtx, c, map[string]any{
			"op": dOpIdentify,
			"d": map[string]any{
				"token":   token,
				"intents": discordDMIntents,
				"properties": map[string]string{
					"os":      "linux",
					"browser": "airlock",
					"device":  "airlock",
				},
			},
		}); err != nil {
			return fmt.Errorf("send identify: %w", err)
		}
	}

	// Event loop. Each frame is parsed, sequence number stored, and
	// dispatched. Heartbeat ACKs are short-circuited up to the
	// heartbeat goroutine via gotAck.
	for {
		select {
		case err := <-heartbeatErr:
			return err
		default:
		}

		p, err := readGatewayPayload(wsCtx, c)
		if err != nil {
			return err
		}
		if p.S != 0 {
			conn.mu.Lock()
			conn.lastSeq = p.S
			conn.mu.Unlock()
		}
		switch p.Op {
		case dOpHeartbeat:
			// Server requested an immediate heartbeat.
			conn.mu.Lock()
			seq := conn.lastSeq
			conn.mu.Unlock()
			_ = writeGatewayPayload(wsCtx, c, map[string]any{"op": dOpHeartbeat, "d": seq})
		case dOpHeartbeatACK:
			select {
			case gotAck <- struct{}{}:
			default:
			}
		case dOpReconnect:
			return nil // outer loop will resume
		case dOpInvalidSession:
			// d=true means the session can be resumed; d=false means
			// start fresh. Either way, drop session state on false.
			var canResume bool
			_ = json.Unmarshal(p.D, &canResume)
			if !canResume {
				conn.mu.Lock()
				conn.sessionID = ""
				conn.lastSeq = 0
				conn.resumeURL = ""
				conn.mu.Unlock()
			}
			return nil
		case dOpDispatch:
			d.handleDispatch(wsCtx, br, conn, p)
		}
	}
}

func (d *DiscordDriver) runHeartbeat(ctx context.Context, c *websocket.Conn, conn *discordConn, interval time.Duration, gotAck <-chan struct{}, errCh chan<- error) {
	// First beat is jittered — Discord asks for it.
	jitter := time.Duration(rand.Int63n(int64(interval)))
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter):
	}

	for {
		conn.mu.Lock()
		seq := conn.lastSeq
		conn.mu.Unlock()
		if err := writeGatewayPayload(ctx, c, map[string]any{"op": dOpHeartbeat, "d": seq}); err != nil {
			select {
			case errCh <- fmt.Errorf("heartbeat send: %w", err):
			default:
			}
			return
		}
		// Wait for ACK before next beat. If none arrives by the
		// next interval, the connection is dead — close and bail
		// so the outer loop reconnects.
		ackTimer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			ackTimer.Stop()
			return
		case <-gotAck:
			ackTimer.Stop()
		case <-ackTimer.C:
			_ = c.Close(websocket.StatusGoingAway, "no heartbeat ack")
			select {
			case errCh <- errors.New("heartbeat ack timeout"):
			default:
			}
			return
		}
		// Sleep the rest of the interval before the next beat.
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// handleDispatch processes an op-0 event. We only care about READY,
// MESSAGE_CREATE, and INTERACTION_CREATE; everything else is ignored
// silently (we don't subscribe to most of it via intents anyway).
func (d *DiscordDriver) handleDispatch(ctx context.Context, br dbq.Bridge, conn *discordConn, p gatewayPayload) {
	switch p.T {
	case "READY":
		var r struct {
			SessionID        string `json:"session_id"`
			ResumeGatewayURL string `json:"resume_gateway_url"`
			User             struct {
				ID       string `json:"id"`
				Username string `json:"username"`
			} `json:"user"`
			Application struct {
				ID string `json:"id"`
			} `json:"application"`
		}
		if err := json.Unmarshal(p.D, &r); err != nil {
			d.logger.Warn("discord: bad READY payload", zap.Error(err))
			return
		}
		conn.mu.Lock()
		conn.sessionID = r.SessionID
		conn.resumeURL = r.ResumeGatewayURL
		conn.botUserID = r.User.ID
		conn.botUsername = r.User.Username
		if r.Application.ID != "" {
			conn.applicationID = r.Application.ID
		}
		conn.mu.Unlock()

	case "MESSAGE_CREATE":
		var m discordMessage
		if err := json.Unmarshal(p.D, &m); err != nil {
			d.logger.Warn("discord: bad MESSAGE_CREATE", zap.Error(err))
			return
		}
		// DM-only: drop guild messages defensively. With GUILD_MESSAGES
		// intent off we shouldn't even receive these; the guard is here
		// in case someone re-enables the intent and forgets the filter.
		if m.GuildID != "" {
			return
		}
		conn.mu.Lock()
		myID := conn.botUserID
		conn.mu.Unlock()
		// Drop our own messages — without this, every reply we send
		// boomerangs straight back through the gateway.
		if m.Author.ID == myID || m.Author.Bot {
			return
		}
		ev := d.messageToEvent(ctx, br, m)
		select {
		case conn.events <- ev:
		case <-ctx.Done():
		}

	case "INTERACTION_CREATE":
		var iv discordInteraction
		if err := json.Unmarshal(p.D, &iv); err != nil {
			d.logger.Warn("discord: bad INTERACTION_CREATE", zap.Error(err))
			return
		}
		switch iv.Type {
		case dInteractionTypeApplicationCommand:
			d.handleSlashInteraction(ctx, br, conn, iv, p.D)
			return
		case dInteractionTypeMessageComponent:
			// Button tap — fall through to the existing button code below.
		default:
			return
		}
		// Ack within 3s — type 6 (DEFERRED_UPDATE_MESSAGE) keeps the
		// original message visible while the agent processes the
		// callback. Errors here aren't fatal; if Discord drops the
		// interaction, the user just sees the spinner timeout.
		_ = d.respondInteractionDeferred(ctx, br.BotTokenRef, iv.ID, iv.Token)

		ev := BridgeEvent{
			BridgeID:   pgUUID(br.ID),
			ExternalID: iv.ChannelID,
			SenderID:   iv.UserID(),
			SenderName: iv.UserName(),
			Callback:   &BridgeCallback{Data: iv.Data.CustomID, AckID: iv.Token},
			RawPayload: p.D,
		}
		select {
		case conn.events <- ev:
		case <-ctx.Done():
		}
	}
}

// botUserIDFor returns the bot user ID for a bridge if a Gateway
// connection is currently active, else "". Used to mark a referenced
// message as FromBot when relevant.
func (d *DiscordDriver) botUserIDFor(br dbq.Bridge) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if conn, ok := d.bridges[pgUUID(br.ID)]; ok {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.botUserID
	}
	return ""
}

// discordReferenced extracts a normalized reference (reply target or
// forward source) from a Discord message, if any. Reply replies have
// `referenced_message` populated; forwards have `message_snapshots`.
// Returns nil when the message references nothing.
func discordReferenced(m discordMessage, botUserID string) *BridgeReferencedMessage {
	if m.ReferencedMessage != nil {
		ref := m.ReferencedMessage
		fromBot := botUserID != "" && ref.Author.ID == botUserID
		return &BridgeReferencedMessage{
			Kind:       BridgeReferenceReply,
			SenderName: ref.Author.Username,
			Text:       ref.Content,
			AuthoredAt: parseDiscordTimestamp(ref.Timestamp),
			FromBot:    fromBot,
		}
	}
	if len(m.MessageSnapshots) > 0 {
		snap := m.MessageSnapshots[0].Message
		var name string
		if snap.Author != nil {
			name = snap.Author.Username
		}
		return &BridgeReferencedMessage{
			Kind:       BridgeReferenceForward,
			SenderName: name,
			Text:       snap.Content,
			AuthoredAt: parseDiscordTimestamp(snap.Timestamp),
		}
	}
	return nil
}

func parseDiscordTimestamp(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (d *DiscordDriver) messageToEvent(ctx context.Context, br dbq.Bridge, m discordMessage) BridgeEvent {
	ev := BridgeEvent{
		BridgeID:          pgUUID(br.ID),
		ExternalID:        m.ChannelID,
		SenderID:          m.Author.ID,
		SenderName:        m.Author.Username,
		Text:              m.Content,
		ReferencedMessage: discordReferenced(m, d.botUserIDFor(br)),
	}
	for _, a := range m.Attachments {
		data, err := d.downloadAttachment(ctx, a.URL)
		if err != nil {
			d.logger.Warn("discord: download attachment failed",
				zap.String("filename", a.Filename),
				zap.Error(err),
			)
			continue
		}
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		ev.Files = append(ev.Files, BridgeFile{
			FileID:      a.ID,
			Filename:    a.Filename,
			ContentType: ct,
			Size:        a.Size,
			Data:        data,
		})
	}
	return ev
}

// --- REST helpers ---

type discordBotInfo struct {
	UserID        string
	Username      string
	ApplicationID string
}

func (d *DiscordDriver) fetchBotInfo(ctx context.Context, token string) (discordBotInfo, error) {
	var me struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := d.callDiscord(ctx, token, http.MethodGet, d.api()+"/users/@me", nil, &me); err != nil {
		return discordBotInfo{}, fmt.Errorf("get user/@me: %w", err)
	}
	var app struct {
		ID string `json:"id"`
	}
	// The bot's application_id == the bot user's snowflake when the
	// bot is owned by the same app, but the canonical place to read
	// it is /oauth2/applications/@me.
	if err := d.callDiscord(ctx, token, http.MethodGet, d.api()+"/oauth2/applications/@me", nil, &app); err != nil {
		return discordBotInfo{}, fmt.Errorf("get application/@me: %w", err)
	}
	return discordBotInfo{UserID: me.ID, Username: me.Username, ApplicationID: app.ID}, nil
}

// GetMe is the public-facing token validator used by the bridge create
// handler. Returns the bot's username for storage on the bridge row.
func (d *DiscordDriver) GetMe(ctx context.Context, token string) (string, error) {
	info, err := d.fetchBotInfo(ctx, token)
	if err != nil {
		return "", err
	}
	return info.Username, nil
}

// DiscordUserInfo is the slice of /users/{id} we surface in identity
// linking. AvatarURL is the resolved CDN URL ("" if the user has no
// avatar set) so callers don't have to know the snowflake-hash format.
type DiscordUserInfo struct {
	ID          string
	Username    string // legacy @handle (no discriminator)
	GlobalName  string // newer "display name" (Discord rolled out 2023)
	AvatarURL   string
}

// FetchUser hits GET /users/{id} for a snowflake. Bot tokens have
// permission to look up any user by ID, returning the public-profile
// fields (username, global_name, avatar). Used by the identity-linking
// preview so the user can verify which Discord account is about to bind.
func (d *DiscordDriver) FetchUser(ctx context.Context, token, userID string) (DiscordUserInfo, error) {
	var u struct {
		ID         string `json:"id"`
		Username   string `json:"username"`
		GlobalName string `json:"global_name"`
		Avatar     string `json:"avatar"`
	}
	if err := d.callDiscord(ctx, token, http.MethodGet, d.api()+"/users/"+userID, nil, &u); err != nil {
		return DiscordUserInfo{}, err
	}
	info := DiscordUserInfo{ID: u.ID, Username: u.Username, GlobalName: u.GlobalName}
	if u.Avatar != "" {
		// Animated avatars (a_-prefixed hash) are GIFs; static are PNGs.
		ext := "png"
		if strings.HasPrefix(u.Avatar, "a_") {
			ext = "gif"
		}
		info.AvatarURL = "https://cdn.discordapp.com/avatars/" + u.ID + "/" + u.Avatar + "." + ext
	}
	return info, nil
}

// CreateDMChannel opens (or fetches) a DM channel with a recipient and
// returns its channel ID. Idempotent — Discord returns the same channel
// every time for a given (bot, user) pair.
func (d *DiscordDriver) CreateDMChannel(ctx context.Context, token, recipientID string) (string, error) {
	var resp struct {
		ID string `json:"id"`
	}
	body := map[string]any{"recipient_id": recipientID}
	if err := d.callDiscord(ctx, token, http.MethodPost, d.api()+"/users/@me/channels", body, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

// SendDM is a convenience wrapper that opens (or reuses) a DM channel
// with a user and posts a plain-text message. Used by the bridge layer
// for the identity-linking prompt so the link is never posted publicly.
func (d *DiscordDriver) SendDM(ctx context.Context, token, recipientID, content string) error {
	channelID, err := d.CreateDMChannel(ctx, token, recipientID)
	if err != nil {
		return fmt.Errorf("open dm: %w", err)
	}
	_, err = d.sendMessage(ctx, token, channelID, content, nil)
	return err
}

// gatewayURL returns the Resume Gateway URL when one is cached (so we
// hit the same edge node on resume), else fetches /gateway/bot.
func (d *DiscordDriver) gatewayURL(ctx context.Context, token string, conn *discordConn) (string, error) {
	conn.mu.Lock()
	resumeURL := conn.resumeURL
	conn.mu.Unlock()
	if resumeURL != "" {
		return resumeURL, nil
	}
	var resp struct {
		URL string `json:"url"`
	}
	if err := d.callDiscord(ctx, token, http.MethodGet, d.api()+"/gateway/bot", nil, &resp); err != nil {
		return "", err
	}
	return resp.URL, nil
}

func (d *DiscordDriver) sendMessage(ctx context.Context, token, channelID, content string, components []map[string]any) (string, error) {
	body := map[string]any{
		"content": content,
	}
	if len(components) > 0 {
		body["components"] = components
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := d.callDiscord(ctx, token, http.MethodPost, d.api()+"/channels/"+channelID+"/messages", body, &resp); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (d *DiscordDriver) sendFile(ctx context.Context, token, channelID string, data []byte, filename, caption string) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	payload := map[string]any{}
	if caption != "" {
		payload["content"] = caption
	}
	pj, _ := json.Marshal(payload)
	pjPart, _ := w.CreateFormField("payload_json")
	pjPart.Write(pj)
	filePart, _ := w.CreateFormFile("files[0]", filename)
	filePart.Write(data)
	w.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.api()+"/channels/"+channelID+"/messages", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bot "+token)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("User-Agent", "DiscordBot (airlock, 1)")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord sendFile: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (d *DiscordDriver) downloadAttachment(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// keepTyping fires POST /channels/{id}/typing every ~8s for as long as
// ctx is alive. Discord clears the indicator after 10s on its own.
func (d *DiscordDriver) keepTyping(ctx context.Context, token, channelID string) func() {
	_ = d.callDiscord(ctx, token, http.MethodPost, d.api()+"/channels/"+channelID+"/typing", nil, nil)
	tickCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(8 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-tickCtx.Done():
				return
			case <-t.C:
				_ = d.callDiscord(tickCtx, token, http.MethodPost, d.api()+"/channels/"+channelID+"/typing", nil, nil)
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// respondInteractionDeferred acks a button tap with type 6
// (DEFERRED_UPDATE_MESSAGE). The original message stays visible; we
// don't follow up via /interactions/{id}/{token}/callback because the
// agent's reply will already arrive as a normal channel message.
func (d *DiscordDriver) respondInteractionDeferred(ctx context.Context, token, interactionID, interactionToken string) error {
	url := d.api() + "/interactions/" + interactionID + "/" + interactionToken + "/callback"
	body := map[string]any{"type": dInteractionRespondDeferredUpdate}
	return d.callDiscord(ctx, token, http.MethodPost, url, body, nil)
}

// respondInteractionEphemeral acks a slash command with type 4
// (CHANNEL_MESSAGE_WITH_SOURCE) and ephemeral flag, so the user sees an
// immediate confirmation while the actual agent reply lands as a
// regular channel message a moment later.
func (d *DiscordDriver) respondInteractionEphemeral(ctx context.Context, token, interactionID, interactionToken, content string) error {
	url := d.api() + "/interactions/" + interactionID + "/" + interactionToken + "/callback"
	body := map[string]any{
		"type": dInteractionRespondMessage,
		"data": map[string]any{
			"content": content,
			"flags":   dMessageFlagEphemeral,
		},
	}
	return d.callDiscord(ctx, token, http.MethodPost, url, body, nil)
}

// handleSlashInteraction routes a slash command into the normal text
// pipeline: reconstruct `/name [args]` from the interaction data, ack
// the interaction within 3s with an ephemeral marker, then push it as
// a BridgeEvent. The agent's reply lands as a regular channel message —
// if the user isn't linked yet, BridgeManager.HandleEvent sends them
// the linking URL on that channel, same as a typed message.
func (d *DiscordDriver) handleSlashInteraction(ctx context.Context, br dbq.Bridge, conn *discordConn, iv discordInteraction, raw json.RawMessage) {
	if err := d.respondInteractionEphemeral(ctx, br.BotTokenRef, iv.ID, iv.Token, "✓"); err != nil {
		d.logger.Warn("discord: ack slash interaction failed",
			zap.String("command", iv.Data.Name),
			zap.Error(err),
		)
		// Continue anyway — even an unacked interaction's text should
		// still flow into the pipeline; the agent reply will land but
		// the user sees Discord's "did not respond" warning.
	}

	var sb strings.Builder
	sb.WriteByte('/')
	sb.WriteString(iv.Data.Name)
	for _, opt := range iv.Data.Options {
		sb.WriteByte(' ')
		sb.WriteString(fmt.Sprint(opt.Value))
	}

	ev := BridgeEvent{
		BridgeID:   pgUUID(br.ID),
		ExternalID: iv.ChannelID,
		SenderID:   iv.UserID(),
		SenderName: iv.UserName(),
		Text:       sb.String(),
		RawPayload: raw,
	}
	select {
	case conn.events <- ev:
	case <-ctx.Done():
	}
}

// callDiscord is the shared REST helper. 429s are retried once after
// honoring Retry-After; everything else returns the error.
func (d *DiscordDriver) callDiscord(ctx context.Context, token, method, url string, body any, out any) error {
	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
	}
	doRequest := func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bot "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("User-Agent", "DiscordBot (airlock, 1)")
		return d.httpClient.Do(req)
	}

	resp, err := doRequest()
	if err != nil {
		return fmt.Errorf("discord %s %s: %w", method, url, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		resp.Body.Close()
		secs, _ := strconv.ParseFloat(retryAfter, 64)
		if secs <= 0 {
			secs = 1
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(secs * float64(time.Second))):
		}
		resp, err = doRequest()
		if err != nil {
			return fmt.Errorf("discord %s %s (retry): %w", method, url, err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord %s %s: status %d: %s", method, url, resp.StatusCode, string(respBody))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (d *DiscordDriver) api() string {
	if d.apiBase != "" {
		return d.apiBase
	}
	return "https://discord.com/api/v10"
}

// --- Formatting helpers ---

// Discord supports a Markdown subset natively (bold, italic, code, code
// blocks). LLM output is already Markdown, so we pass it through as-is
// and only apply minimal formatting to tool bubbles.

func formatDiscordToolCall(toolName, input string) string {
	if input == "" {
		return "▶ **" + toolName + "**"
	}
	// Try to extract the single arg if there's only one; otherwise dump
	// the whole JSON. Matches Telegram's behavior.
	var args map[string]any
	if json.Unmarshal([]byte(input), &args) == nil && len(args) == 1 {
		for _, v := range args {
			return "▶ **" + toolName + "**\n```\n" + fmt.Sprint(v) + "\n```"
		}
	}
	return "▶ **" + toolName + "**\n```json\n" + input + "\n```"
}

func formatDiscordToolResult(toolName, output, toolError string) string {
	if toolError != "" {
		return "✗ **" + toolName + "**: " + toolError
	}
	if output == "" {
		return "✓ **" + toolName + "**"
	}
	if len(output) > 500 {
		output = output[:500] + "…"
	}
	return "✓ **" + toolName + "**\n```\n" + output + "\n```"
}

func formatDiscordConfirmation(permission string, patterns []string, code string) string {
	_ = patterns
	var sb strings.Builder
	sb.WriteString("🔐 **Confirmation required**")
	if permission != "" {
		sb.WriteString("\nPermission: `")
		sb.WriteString(permission)
		sb.WriteString("`")
	}
	if code != "" {
		sb.WriteString("\n```\n")
		sb.WriteString(code)
		sb.WriteString("\n```")
	}
	return sb.String()
}

// discordApprovalButtons builds an action row with approve / deny buttons.
// custom_id carries the runID payload — Discord echoes it back verbatim
// in the INTERACTION_CREATE event we route as a BridgeCallback.
func discordApprovalButtons(runID string) []map[string]any {
	return []map[string]any{
		{
			"type": 1, // ACTION_ROW
			"components": []map[string]any{
				{
					"type":      2, // BUTTON
					"style":     3, // SUCCESS (green)
					"label":     "✅ Approve",
					"custom_id": "approve:" + runID,
				},
				{
					"type":      2,
					"style":     4, // DANGER (red)
					"label":     "❌ Deny",
					"custom_id": "deny:" + runID,
				},
			},
		},
	}
}

// --- Gateway types ---

type gatewayPayload struct {
	Op int             `json:"op"`
	D  json.RawMessage `json:"d"`
	S  int64           `json:"s"`
	T  string          `json:"t"`
}

func readGatewayPayload(ctx context.Context, c *websocket.Conn) (gatewayPayload, error) {
	_, data, err := c.Read(ctx)
	if err != nil {
		return gatewayPayload{}, err
	}
	var p gatewayPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return gatewayPayload{}, fmt.Errorf("parse gateway payload: %w", err)
	}
	return p, nil
}

func writeGatewayPayload(ctx context.Context, c *websocket.Conn, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, data)
}

type discordMessage struct {
	ID                string              `json:"id"`
	ChannelID         string              `json:"channel_id"`
	GuildID           string              `json:"guild_id"`
	Content           string              `json:"content"`
	Author            discordUser         `json:"author"`
	Attachments       []discordAttachment `json:"attachments"`
	Type              int                 `json:"type"`
	Components        []map[string]any    `json:"components"`
	Timestamp         string              `json:"timestamp"` // ISO8601, used for ReferencedMessage.AuthoredAt
	ReferencedMessage *discordMessage     `json:"referenced_message"`
	MessageSnapshots  []discordSnapshot   `json:"message_snapshots"`
}

// discordSnapshot is the slice of a forwarded message's payload Discord
// returns inline on MESSAGE_CREATE for forward-type messages.
type discordSnapshot struct {
	Message struct {
		Content   string `json:"content"`
		Timestamp string `json:"timestamp"`
		Author    *discordUser `json:"author"`
	} `json:"message"`
}

type discordUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Bot      bool   `json:"bot"`
}

type discordAttachment struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	URL         string `json:"url"`
}

// discordInteraction covers the slice of the full interaction payload we
// care about for component (button) interactions.
type discordInteraction struct {
	ID        string                 `json:"id"`
	Token     string                 `json:"token"`
	Type      int                    `json:"type"`
	ChannelID string                 `json:"channel_id"`
	Data      discordInteractionData `json:"data"`
	Member    *discordMember         `json:"member"`
	User      *discordUser           `json:"user"`
}

type discordInteractionData struct {
	CustomID string                     `json:"custom_id"` // for component interactions
	Name     string                     `json:"name"`      // for application_command
	Options  []discordInteractionOption `json:"options"`   // for application_command
}

type discordInteractionOption struct {
	Name  string `json:"name"`
	Type  int    `json:"type"`
	Value any    `json:"value"`
}

type discordMember struct {
	User discordUser `json:"user"`
}

func (i discordInteraction) UserID() string {
	if i.User != nil {
		return i.User.ID
	}
	if i.Member != nil {
		return i.Member.User.ID
	}
	return ""
}

func (i discordInteraction) UserName() string {
	if i.User != nil {
		return i.User.Username
	}
	if i.Member != nil {
		return i.Member.User.Username
	}
	return ""
}

// discordBridgeConfig is the JSONB payload stored in bridges.config for
// Discord bridges. ApplicationID is set in Init from /oauth2/applications/@me
// so the slash-command registrar doesn't re-fetch on every restart.
type discordBridgeConfig struct {
	ApplicationID string `json:"application_id"`
}

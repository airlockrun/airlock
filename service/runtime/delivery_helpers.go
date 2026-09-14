package runtime

import (
	"strings"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
)

// ExtractTextSummary builds a text summary from display parts for the content column.
func ExtractTextSummary(parts []wire.DisplayPart) string {
	var sb strings.Builder
	for _, p := range parts {
		switch p.Type {
		case "text":
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(p.Text)
		case "image", "file", "audio", "video":
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			name := p.Filename
			if name == "" {
				name = p.Type
			}
			sb.WriteString("[" + name + "]")
			if p.Text != "" {
				sb.WriteString(" " + p.Text)
			}
		}
	}
	return sb.String()
}

// agentMediaKey builds the S3 key for permanent media storage.
func agentMediaKey(agentID uuid.UUID, mediaID, filename string) string {
	return "agents/" + agentID.String() + "/media/" + mediaID + "/" + filename
}

func ValidMediaFilename(filename string) bool {
	cleaned, err := storage.CleanAgentPath(filename)
	return err == nil && cleaned == filename && !strings.Contains(filename, "/")
}

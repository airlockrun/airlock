// Package locale validates the persisted UI locale and renders soft language
// guidance for human-facing LLM output.
package locale

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/text/language"
)

const MaxLength = 63

var canonicalPattern = regexp.MustCompile(`^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-(?:[A-Z]{2}|[0-9]{3}))?(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*(?:-[0-9a-wy-z](?:-[a-z0-9]{2,8})+)*(?:-x(?:-[a-z0-9]{1,8})+)?$`)
var inputPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// Canonicalize parses a locale and returns its canonical BCP 47 form.
func Canonicalize(value string) (string, error) {
	if value == "" {
		return "", errors.New("locale is required")
	}
	if !inputPattern.MatchString(value) {
		return "", errors.New("locale must be a valid BCP 47 language tag")
	}
	if !hasUniqueVariantsAndExtensions(value) {
		return "", errors.New("locale must be a valid BCP 47 language tag")
	}
	tag, err := language.BCP47.Parse(value)
	if err != nil {
		return "", errors.New("locale must be a valid BCP 47 language tag")
	}
	canonical := tag.String()
	if canonical == language.Und.String() || len(canonical) > MaxLength || !canonicalPattern.MatchString(canonical) {
		return "", errors.New("locale must be a supported BCP 47 language tag of at most 63 characters")
	}
	return canonical, nil
}

func hasUniqueVariantsAndExtensions(value string) bool {
	parts := strings.Split(strings.ToLower(value), "-")
	i := 1
	if i < len(parts) && len(parts[i]) == 4 {
		i++
	}
	if i < len(parts) && (len(parts[i]) == 2 || len(parts[i]) == 3) {
		i++
	}
	variants := make(map[string]struct{})
	for i < len(parts) && (len(parts[i]) >= 5 || len(parts[i]) == 4) {
		if _, exists := variants[parts[i]]; exists {
			return false
		}
		variants[parts[i]] = struct{}{}
		i++
	}
	extensions := make(map[string]struct{})
	for i < len(parts) {
		singleton := parts[i]
		if singleton == "x" {
			return true
		}
		if _, exists := extensions[singleton]; exists {
			return false
		}
		extensions[singleton] = struct{}{}
		i++
		for i < len(parts) && len(parts[i]) != 1 {
			i++
		}
	}
	return true
}

// ReplyInstruction returns soft language guidance for human-facing replies.
func ReplyInstruction(value string) string {
	return "Locale " + value + " is the preferred default for human-facing replies. Explicit user requests and the conversation's established language take precedence. Preserve code, identifiers, commands, paths, URLs, logs, schema keys, tool/external data, and quotes."
}

// AppendReplyInstruction appends locale guidance to existing prompt instructions.
func AppendReplyInstruction(instructions, value string) string {
	if instructions == "" {
		return ReplyInstruction(value)
	}
	return instructions + "\n\n" + ReplyInstruction(value)
}

// BuildInstruction returns language guidance for generated human-authored UI copy.
func BuildInstruction(value string, upgrade bool) string {
	if upgrade {
		return "Preserve the existing application's language unless the user explicitly asks to translate it. For new human-authored web UI copy without an established application language, locale " + value + " is the preferred default. Explicit user requests and the conversation's established language take precedence. Preserve code, identifiers, commands, paths, URLs, logs, schema keys, tool/external data, and quotes."
	}
	return "For new human-authored web UI copy, locale " + value + " is the preferred default. Explicit user requests and the conversation's established language take precedence. Preserve code, identifiers, commands, paths, URLs, logs, schema keys, tool/external data, and quotes."
}

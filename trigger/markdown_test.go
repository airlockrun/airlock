package trigger

import (
	"strings"
	"testing"
)

func TestMarkdownToTelegramHTML(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain text", "hello world", "hello world"},
		{"bold", "**bold**", "<b>bold</b>"},
		{"italic with asterisk", "*italic*", "<i>italic</i>"},
		{"italic with underscore", "_italic_", "<i>italic</i>"},
		{"bold and italic mixed", "**bold** and *italic*", "<b>bold</b> and <i>italic</i>"},
		{"inline code", "use `foo()` please", "use <code>foo()</code> please"},
		{"fenced code with lang", "```go\nx := 1\n```", "<pre><code class=\"language-go\">x := 1\n</code></pre>"},
		{"fenced code no lang", "```\nplain\n```", "<pre>plain\n</pre>"},
		{"link", "[click](https://example.com)", `<a href="https://example.com">click</a>`},
		{"autolink linkify", "visit https://example.com now", `visit <a href="https://example.com">https://example.com</a> now`},
		{"heading h1", "# Title", "<b>Title</b>"},
		{"heading h3", "### Sub", "<b>Sub</b>"},
		{"unordered list dash", "- one\n- two", "• one\n• two"},
		{"unordered list star", "* a\n* b", "• a\n• b"},
		{"ordered list", "1. a\n2. b", "1. a\n2. b"},
		{"list with bold item", "- **Morning** mix\n- Energy boost", "• <b>Morning</b> mix\n• Energy boost"},
		{"strikethrough", "~~gone~~", "<s>gone</s>"},
		{"html escape in text", "a < b & c > d", "a &lt; b &amp; c &gt; d"},
		{"raw html inside bold dropped", "**a<b>c**", "<b>ac</b>"},
		{"blockquote", "> quoted line", "<blockquote>quoted line</blockquote>"},
		{"horizontal rule", "before\n\n---\n\nafter", "before\n\n———\n\nafter"},
		{"raw html tags dropped, text between stays", "hello <script>alert(1)</script> world", "hello alert(1) world"},
		{"image becomes link", "![alt](https://example.com/img.png)", `<a href="https://example.com/img.png">alt</a>`},
		{
			name: "realistic LLM output",
			in:   "Отличный запрос ☀️\n\n- **Morning Motivation** — поп/электро\n- **Cardio** — если хочется разогнаться\n\nНапиши номер!",
			want: "Отличный запрос ☀️\n\n• <b>Morning Motivation</b> — поп/электро\n• <b>Cardio</b> — если хочется разогнаться\n\nНапиши номер!",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := markdownToTelegramHTML(tc.in)
			if got != tc.want {
				t.Errorf("input:\n%q\ngot:\n%q\nwant:\n%q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMarkdownToTelegramHTML_NestedEmphasis(t *testing.T) {
	// Bold containing italic — goldmark parses this as Emphasis(level=2)
	// wrapping an Emphasis(level=1).
	got := markdownToTelegramHTML("**bold _and italic_**")
	want := "<b>bold <i>and italic</i></b>"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMarkdownToTelegramHTML_PreservesCodeNewlines(t *testing.T) {
	// A multi-line tool output in a fenced block keeps its line breaks.
	in := "```\nline1\nline2\nline3\n```"
	got := markdownToTelegramHTML(in)
	if !strings.Contains(got, "line1\nline2\nline3\n") {
		t.Errorf("expected real newlines in code block, got %q", got)
	}
}

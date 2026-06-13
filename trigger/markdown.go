package trigger

import (
	"fmt"
	"html"
	"strings"
	"unicode"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
)

// tgParser parses the CommonMark + GFM subset the LLM tends to emit.
// Strikethrough, Linkify and Table are the GFM features worth handling;
// task lists are rare in chat output and render acceptably as plain
// lists. Telegram has no table markup, so a GFM table is flattened to a
// monospace <pre> block — see renderTelegramTable.
var tgParser = goldmark.New(
	goldmark.WithExtensions(extension.Strikethrough, extension.Linkify, extension.Table),
).Parser()

// markdownToTelegramHTML converts LLM markdown output into the HTML subset
// accepted by Telegram's parse_mode=HTML. Unsupported block constructs
// (headings, lists, horizontal rules) are flattened: headings become bold
// paragraphs, list items get a bullet or number prefix, HRs become a dash
// separator. Plain text is HTML-escaped.
func markdownToTelegramHTML(src string) string {
	if strings.TrimSpace(src) == "" {
		return ""
	}
	doc := tgParser.Parse(text.NewReader([]byte(src)))
	var b strings.Builder
	walkMD(&b, []byte(src), doc, 0)
	return strings.TrimRight(b.String(), "\n")
}

func walkMD(b *strings.Builder, src []byte, n ast.Node, depth int) {
	switch node := n.(type) {
	case *ast.Document, *ast.TextBlock:
		walkChildren(b, src, node, depth)

	case *ast.Paragraph:
		walkChildren(b, src, node, depth)
		b.WriteString("\n\n")

	case *ast.Heading:
		b.WriteString("<b>")
		walkChildren(b, src, node, depth)
		b.WriteString("</b>\n\n")

	case *ast.Blockquote:
		var inner strings.Builder
		walkChildren(&inner, src, node, depth)
		b.WriteString("<blockquote>")
		b.WriteString(strings.TrimSpace(inner.String()))
		b.WriteString("</blockquote>\n\n")

	case *ast.FencedCodeBlock:
		b.WriteString("<pre>")
		lang := string(node.Language(src))
		if lang != "" {
			fmt.Fprintf(b, `<code class="language-%s">`, html.EscapeString(lang))
		}
		writeCodeLines(b, src, node)
		if lang != "" {
			b.WriteString("</code>")
		}
		b.WriteString("</pre>\n\n")

	case *ast.CodeBlock:
		b.WriteString("<pre>")
		writeCodeLines(b, src, node)
		b.WriteString("</pre>\n\n")

	case *ast.List:
		walkList(b, src, node, depth)

	case *extast.Table:
		renderTelegramTable(b, src, node)

	case *ast.ThematicBreak:
		b.WriteString("———\n\n")

	case *ast.Text:
		b.WriteString(html.EscapeString(string(node.Value(src))))
		if node.HardLineBreak() || node.SoftLineBreak() {
			b.WriteString("\n")
		}

	case *ast.String:
		b.WriteString(html.EscapeString(string(node.Value)))

	case *ast.CodeSpan:
		b.WriteString("<code>")
		writeInlineText(b, src, node)
		b.WriteString("</code>")

	case *ast.Emphasis:
		tag := "i"
		if node.Level == 2 {
			tag = "b"
		}
		b.WriteString("<")
		b.WriteString(tag)
		b.WriteString(">")
		walkChildren(b, src, node, depth)
		b.WriteString("</")
		b.WriteString(tag)
		b.WriteString(">")

	case *ast.Link:
		b.WriteString(`<a href="`)
		b.WriteString(html.EscapeString(string(node.Destination)))
		b.WriteString(`">`)
		walkChildren(b, src, node, depth)
		b.WriteString("</a>")

	case *ast.AutoLink:
		url := string(node.URL(src))
		b.WriteString(`<a href="`)
		b.WriteString(html.EscapeString(url))
		b.WriteString(`">`)
		b.WriteString(html.EscapeString(url))
		b.WriteString("</a>")

	case *ast.Image:
		// Telegram HTML can't render inline images — fall back to a link
		// with the alt text as the label.
		alt := extractText(src, node)
		if alt == "" {
			alt = string(node.Destination)
		}
		b.WriteString(`<a href="`)
		b.WriteString(html.EscapeString(string(node.Destination)))
		b.WriteString(`">`)
		b.WriteString(html.EscapeString(alt))
		b.WriteString("</a>")

	case *extast.Strikethrough:
		b.WriteString("<s>")
		walkChildren(b, src, node, depth)
		b.WriteString("</s>")

	case *ast.RawHTML, *ast.HTMLBlock:
		// Pass-through would risk Telegram rejecting the message with
		// "unsupported start tag". Drop silently — the surrounding prose
		// almost always carries the meaning.

	default:
		walkChildren(b, src, n, depth)
	}
}

func walkChildren(b *strings.Builder, src []byte, n ast.Node, depth int) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		walkMD(b, src, c, depth)
	}
}

func walkList(b *strings.Builder, src []byte, list *ast.List, depth int) {
	indent := strings.Repeat("  ", depth)
	idx := 0
	for c := list.FirstChild(); c != nil; c = c.NextSibling() {
		item, ok := c.(*ast.ListItem)
		if !ok {
			continue
		}
		idx++
		b.WriteString(indent)
		if list.IsOrdered() {
			fmt.Fprintf(b, "%d. ", idx)
		} else {
			b.WriteString("• ")
		}
		var inner strings.Builder
		for cc := item.FirstChild(); cc != nil; cc = cc.NextSibling() {
			if sub, ok := cc.(*ast.List); ok {
				inner.WriteString("\n")
				walkList(&inner, src, sub, depth+1)
				continue
			}
			walkMD(&inner, src, cc, depth+1)
		}
		b.WriteString(strings.TrimRight(inner.String(), "\n"))
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func writeCodeLines(b *strings.Builder, src []byte, n ast.Node) {
	lines := n.Lines()
	for i := 0; i < lines.Len(); i++ {
		seg := lines.At(i)
		b.WriteString(html.EscapeString(string(seg.Value(src))))
	}
}

func writeInlineText(b *strings.Builder, src []byte, n ast.Node) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		switch t := c.(type) {
		case *ast.Text:
			b.WriteString(html.EscapeString(string(t.Value(src))))
		case *ast.String:
			b.WriteString(html.EscapeString(string(t.Value)))
		default:
			writeInlineText(b, src, c)
		}
	}
}

func extractText(src []byte, n ast.Node) string {
	var b strings.Builder
	var collect func(ast.Node)
	collect = func(nn ast.Node) {
		for c := nn.FirstChild(); c != nil; c = c.NextSibling() {
			switch t := c.(type) {
			case *ast.Text:
				b.Write(t.Value(src))
			case *ast.String:
				b.Write(t.Value)
			default:
				collect(c)
			}
		}
	}
	collect(n)
	return b.String()
}

// renderTelegramTable flattens a GFM table into a monospace <pre> block.
// Telegram's HTML has no table markup, but <pre> preserves the column
// alignment of a space-padded ASCII layout. Cell content is reduced to
// plain text — inline formatting can't survive inside <pre>.
func renderTelegramTable(b *strings.Builder, src []byte, table *extast.Table) {
	var rows [][]string
	for c := table.FirstChild(); c != nil; c = c.NextSibling() {
		var cells []string
		for cell := c.FirstChild(); cell != nil; cell = cell.NextSibling() {
			cells = append(cells, strings.TrimSpace(extractText(src, cell)))
		}
		if len(cells) > 0 {
			rows = append(rows, cells)
		}
	}
	if len(rows) == 0 {
		return
	}

	ncol := 0
	for _, r := range rows {
		if len(r) > ncol {
			ncol = len(r)
		}
	}
	width := make([]int, ncol)
	for _, r := range rows {
		for i, cell := range r {
			if w := len([]rune(cell)); w > width[i] {
				width[i] = w
			}
		}
	}

	b.WriteString("<pre>")
	for ri, r := range rows {
		var line strings.Builder
		for i := 0; i < ncol; i++ {
			cell := ""
			if i < len(r) {
				cell = r[i]
			}
			line.WriteString(cell)
			if i < ncol-1 {
				line.WriteString(strings.Repeat(" ", width[i]-len([]rune(cell))))
				line.WriteString("  ")
			}
		}
		b.WriteString(html.EscapeString(strings.TrimRight(line.String(), " ")))
		b.WriteString("\n")
		if ri == 0 { // underline the header row
			var sep strings.Builder
			for i := 0; i < ncol; i++ {
				sep.WriteString(strings.Repeat("─", width[i]))
				if i < ncol-1 {
					sep.WriteString("  ")
				}
			}
			b.WriteString(html.EscapeString(sep.String()))
			b.WriteString("\n")
		}
	}
	b.WriteString("</pre>\n\n")
}

// telegramTextLimit is the Bot API's hard cap on sendMessage text,
// counted in UTF-16 code units.
const telegramTextLimit = 4096

// utf16Len counts s in UTF-16 code units — the unit Telegram measures
// message length in (a non-BMP rune, e.g. most emoji, costs two).
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// closeTagFor returns the closing tag matching an opening Telegram-HTML
// tag — e.g. `<a href="x">` → `</a>`, `<code class="...">` → `</code>`.
func closeTagFor(openTag string) string {
	name := strings.TrimPrefix(openTag, "<")
	if i := strings.IndexAny(name, " >"); i >= 0 {
		name = name[:i]
	}
	return "</" + name + ">"
}

// telegramAtoms splits Telegram-HTML into indivisible atoms — each whole
// tag, each whitespace run, each word — so a chunk boundary never lands
// inside a tag or mid-word. A word longer than max is rune-sliced, so no
// atom can exceed the chunk budget on its own.
func telegramAtoms(s string, max int) []string {
	var atoms []string
	add := func(a string) {
		if !strings.HasPrefix(a, "<") {
			for utf16Len(a) > max {
				ar := []rune(a)
				cut, w := len(ar), 0
				for k, r := range ar {
					if r > 0xFFFF {
						w += 2
					} else {
						w++
					}
					if w > max {
						cut = k
						break
					}
				}
				if cut == 0 {
					cut = 1
				}
				atoms = append(atoms, string(ar[:cut]))
				a = string(ar[cut:])
			}
		}
		if a != "" {
			atoms = append(atoms, a)
		}
	}
	rs := []rune(s)
	for i := 0; i < len(rs); {
		switch {
		case rs[i] == '<':
			j := i + 1
			for j < len(rs) && rs[j] != '>' {
				j++
			}
			if j < len(rs) {
				j++ // include '>'
			}
			add(string(rs[i:j]))
			i = j
		case unicode.IsSpace(rs[i]):
			j := i
			for j < len(rs) && unicode.IsSpace(rs[j]) {
				j++
			}
			add(string(rs[i:j]))
			i = j
		default:
			j := i
			for j < len(rs) && rs[j] != '<' && !unicode.IsSpace(rs[j]) {
				j++
			}
			add(string(rs[i:j]))
			i = j
		}
	}
	return atoms
}

// splitForTelegram breaks Telegram-HTML into chunks each within the Bot
// API's per-message limit. It splits on word/whitespace boundaries; any
// tag still open at a split is closed at the chunk's end and reopened at
// the next chunk's start, so every chunk is independently valid
// parse_mode=HTML. Returns nil for blank input.
func splitForTelegram(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	if utf16Len(s) <= telegramTextLimit {
		return []string{s}
	}
	// Budget below the hard limit leaves room for the close/reopen tag
	// pair a split inside formatted text adds to the two chunks.
	const budget = 3900
	atoms := telegramAtoms(s, budget)

	var (
		chunks  []string
		open    []string // open-tag stack, outermost first
		cur     strings.Builder
		curLen  int
		content bool // current chunk holds non-whitespace content
	)
	closeAllLen := func() int {
		n := 0
		for _, t := range open {
			n += utf16Len(closeTagFor(t))
		}
		return n
	}
	flush := func() {
		if !content {
			return
		}
		var b strings.Builder
		b.WriteString(cur.String())
		for i := len(open) - 1; i >= 0; i-- {
			b.WriteString(closeTagFor(open[i]))
		}
		chunks = append(chunks, b.String())
		cur.Reset()
		curLen, content = 0, false
		for _, t := range open { // reopen still-open tags on the next chunk
			cur.WriteString(t)
			curLen += utf16Len(t)
		}
	}

	for _, a := range atoms {
		isTag := strings.HasPrefix(a, "<")
		isWS := !isTag && strings.TrimSpace(a) == ""
		// Whitespace at the start of a fresh chunk is dead weight.
		if isWS && !content {
			continue
		}
		if curLen+utf16Len(a)+closeAllLen() > budget {
			flush()
			if isWS {
				continue
			}
		}
		cur.WriteString(a)
		curLen += utf16Len(a)
		switch {
		case !isTag:
			if !isWS {
				content = true
			}
		case strings.HasPrefix(a, "</"):
			if len(open) > 0 {
				open = open[:len(open)-1]
			}
		default:
			open = append(open, a)
		}
	}
	flush()
	return chunks
}

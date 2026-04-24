package trigger

import (
	"fmt"
	"html"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
)

// tgParser parses the CommonMark + GFM subset the LLM tends to emit.
// Strikethrough and Linkify are the two GFM features worth handling;
// tables and task lists are rare in chat output and would render badly
// in Telegram anyway.
var tgParser = goldmark.New(
	goldmark.WithExtensions(extension.Strikethrough, extension.Linkify),
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

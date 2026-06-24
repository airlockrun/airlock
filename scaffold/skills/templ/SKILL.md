---
name: templ
description: templ (a-h/templ) type-safe Go HTML templating — the language used for every .templ file in this agent's web UI. TRIGGER when writing, editing, or debugging any .templ file, or when generated *_templ.go output renders wrong (stray text, duplicated markup, unescaped values).
metadata:
  version: v0.3.1020
  source: https://templ.guide
---

# templ

templ is a Go HTML templating language. `.templ` files compile to `*_templ.go`
(run `templ generate`). Markup lives inside `templ name(args) { ... }` blocks;
everything else in the file is ordinary Go.

## When to run this skill

- Writing or editing any `.templ` file.
- The rendered page shows literal source text (e.g. the word `return`), missing
  markup, or the same block repeated — almost always a control-flow or escaping
  mistake covered below.

## The rules that bite (read before writing templ)

These are the mistakes a Go programmer makes by reflex. templ markup is **not**
a Go function body.

- **Only `if`, `switch`, and `for` are control flow inside a templ block.** There
  is no early `return`, no `break`, no `continue`, no bare statements. A line like
  `return` is **not** an exit — templ treats any text it doesn't recognize as
  literal content and writes it to the output verbatim. To render one of several
  states, use a single `if / else if / else` chain; never `if cond { ...markup... return }`.
  See [./reference/03-syntax-and-usage/05-statements.md](./reference/03-syntax-and-usage/05-statements.md),
  [./reference/03-syntax-and-usage/06-if-else.md](./reference/03-syntax-and-usage/06-if-else.md).
- **Text that must literally start with `if`/`switch`/`for` has to be wrapped**
  (`<p>{ "if you..." }</p>`) or the parser reads it as a control statement. Same file as above.
- **Dynamic values go in `{ ... }` expressions; they are auto-escaped.** Attribute
  values too: `<a href={ url }>`. Don't string-concatenate HTML.
  See [./reference/03-syntax-and-usage/03-attributes.md](./reference/03-syntax-and-usage/03-attributes.md),
  [./reference/03-syntax-and-usage/04-expressions.md](./reference/03-syntax-and-usage/04-expressions.md).
- **Event handlers are NOT Go.** An `onclick` is a quoted JS literal
  (`<button onclick="myFn()">`) or a templ *script template*; you cannot call a Go
  function from `onclick`. Prefer htmx (`hx-*`) for behavior; reserve inline JS for
  the rare client-only case.
  See [./reference/03-syntax-and-usage/13-script-templates.md](./reference/03-syntax-and-usage/13-script-templates.md).
- **Raw, unescaped HTML is opt-in** via `@templ.Raw(...)` — only for trusted content.
  See [./reference/03-syntax-and-usage/17-rendering-raw-html.md](./reference/03-syntax-and-usage/17-rendering-raw-html.md).

## Mandatory reference

| Task | Guide |
|------|-------|
| Control flow (if/switch/for, the no-`return` rule) | [./reference/03-syntax-and-usage/05-statements.md](./reference/03-syntax-and-usage/05-statements.md) |
| Conditionals | [./reference/03-syntax-and-usage/06-if-else.md](./reference/03-syntax-and-usage/06-if-else.md), [07-switch.md](./reference/03-syntax-and-usage/07-switch.md), [08-loops.md](./reference/03-syntax-and-usage/08-loops.md) |
| Expressions & attributes (escaping) | [04-expressions.md](./reference/03-syntax-and-usage/04-expressions.md), [03-attributes.md](./reference/03-syntax-and-usage/03-attributes.md) |
| Composing components / children | [10-template-composition.md](./reference/03-syntax-and-usage/10-template-composition.md), [./reference/04-core-concepts/01-components.md](./reference/04-core-concepts/01-components.md) |
| Inline JS / event handlers | [13-script-templates.md](./reference/03-syntax-and-usage/13-script-templates.md) |
| CSS in templ | [12-css-style-management.md](./reference/03-syntax-and-usage/12-css-style-management.md) |
| htmx fragments (partial swaps) | [19-fragments.md](./reference/03-syntax-and-usage/19-fragments.md) |
| Embedding raw Go | [09-raw-go.md](./reference/03-syntax-and-usage/09-raw-go.md) |
| Rendering raw HTML safely | [17-rendering-raw-html.md](./reference/03-syntax-and-usage/17-rendering-raw-html.md) |
| `context` in templates | [15-context.md](./reference/03-syntax-and-usage/15-context.md) |

Full syntax reference: [./reference/03-syntax-and-usage/](./reference/03-syntax-and-usage/) ·
core concepts: [./reference/04-core-concepts/](./reference/04-core-concepts/).
Read the relevant guide before writing the markup, not after it renders wrong.

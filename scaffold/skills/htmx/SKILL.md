---
name: htmx
description: htmx — HTML-over-the-wire interactivity via hx-* attributes, the interactivity layer for this agent's templ web UI. TRIGGER when adding or debugging any hx-* attribute (hx-get/post/swap/target/trigger), polling, partial page updates, or when a swap duplicates, nests, or fails to update the DOM.
metadata:
  version: v2.0.10
  source: https://htmx.org/docs/
---

# htmx

htmx lets HTML drive AJAX, swaps, and polling through `hx-*` attributes. The
server returns HTML fragments; htmx swaps them into the DOM. It is served
same-origin by the framework (`agentsdk.Assets.HTMX`) — no CDN, no npm.

## When to run this skill

- Adding interactivity to a templ page (`hx-get`, `hx-post`, `hx-trigger`, …).
- A swap behaves wrong: content duplicates, nests inside itself, replaces the
  wrong element, or a poll never stops / resets the page.

## The rules that bite (read before writing hx-*)

- **Decide who owns the swap target, once.** Either the parent element swaps its
  own contents (`hx-target="this" hx-swap="innerHTML"`) **or** the response
  fragment is the new element — never both. Double-wrapping (a fragment that
  re-emits its own container into a container) is the usual cause of duplicated or
  nested cards. See [./reference/docs.md](./reference/docs.md) (swapping & targets).
- **For polling, return `204 No Content` when nothing changed.** htmx treats 204 as
  "do nothing", so an idle page stays put. Make each poll carry what it last saw
  (a query param/header) and return `200` + fresh HTML only on a real change. Use
  **204, not 304** — htmx swaps 3xx/2xx bodies, and a 304 with a stale body can
  blank or reset the view.
- **`hx-swap` controls placement** (`innerHTML` default, `outerHTML`, `beforeend`,
  …) and out-of-band updates use `hx-swap-oob`. Pick the mode deliberately; the
  default `innerHTML` replaces children, `outerHTML` replaces the element itself.
- **Triggers are explicit.** `hx-trigger` (`click`, `load`, `every 2s`,
  `revealed`, modifiers like `delay:`, `from:`) decides when a request fires; the
  default depends on the element. Set it rather than relying on defaults.

## Mandatory reference

| Task | Guide |
|------|-------|
| Core concepts, requests, swapping, targets, polling, OOB | [./reference/docs.md](./reference/docs.md) |
| Every attribute / header / event (lookup table) | [./reference/reference.md](./reference/reference.md) |

`docs.md` is the full narrative guide; `reference.md` is the exhaustive
attribute/header/event index. Read the relevant section before wiring an
interaction, and pair this with the `templ` skill (htmx attributes live in
`.templ` markup, and partial responses are templ fragments).

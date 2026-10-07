# UI design system (proposal, text only)

Status: proposal awaiting approval (revision 2: machine-token-only mono, forced-colors rules, neutral hover, explicit tint tokens,
blockers inside the verdict slot, contrast checker; then dark-only with an opt-in light theme until components migrate). The tokens are in
`frontend/src/theme.css`; no component rule has been migrated yet. It defines the target look and the rules every later
frontend change must follow. It does not redesign the verdict card or the coverage panel: Phase B changes what they say, so this document only defines the
tier styles and reserves their place in the layout.

Method: the `ui-ux-pro-max` skill was run locally (read-only, nothing persisted) and its output treated as recommendations. Section 11 lists what was
adopted and what was rejected. Stack as found in `frontend/package.json`: React 19, Vite, plain CSS files (`theme.css`, `app.css`, `workbench.css`), no
CSS framework, no icon or animation package. That stays true.

## 1. Purpose

This is an analyst workbench for reported emails. It is read by one person at a time who is working through a queue.

- Dense: many facts per screen, small but legible type, tight spacing, little decoration.
- Scannable: the verdict tier, the reasons and the gaps are readable in a few seconds; detail is one click down.
- Evidence first: values from the message (addresses, hosts, headers, text) are the content, shown exactly, wrapped, never styled as trusted.
- Honest: the interface never says more than the analysis established. Absence of indicators is never styled as reassurance.
- Not a marketing site: no hero, no calls to action, no brand colour, no imagery, no motion for effect.

## 2. Hard constraints (apply to every later change)

1. No remote fonts, images, icons, scripts or CSS. System font stack or locally bundled font files only. `src/test/noUnsafeRendering.test.ts` must keep
   passing unchanged (no `<img>`, no remote `url()`, no remote `@import`, no raw HTML rendering).
2. No new dependency (no GSAP, Framer Motion, icon package, CSS framework) without asking first.
3. Every element that can show email content keeps `dir="auto"`. Hebrew and other RTL text must render and wrap correctly.
4. "No indicators found" stays neutral: no green, no check mark, no shield, and it is always shown together with its blockers and the sentence
   "not a safety verdict".
5. Untrusted content is plain text. Links built from message content are defanged and not clickable. The only anchors are the third-party lookup
   links in the indicators panel (`rel="noopener noreferrer"`, `target="_blank"`).
6. Accessibility: text contrast at least 4.5:1, visible focus on every interactive element, full keyboard operation, meaning never carried by colour alone.
7. No decorative animation. Anything that moves respects `prefers-reduced-motion`.
8. Existing tests stay green and are not weakened.
9. Scope: the verdict card and the coverage panel were reserved slots until Phase B; from step 13 (2026-10-07) they are built from `verdict_v2` and `checks_completed` (section 13). The tier labels below are the
   source of truth (D21): Confirmed malicious, Suspicious, Needs analyst, No indicators found.

## 3. Colour tokens

Dark-only for now. The dark tokens are declared on `:root` with `color-scheme: dark`, and every user gets them whatever the operating system setting
is. The light tokens exist and are checked, but they are opt-in: they are declared inside `:root[data-theme="light"] { color-scheme: light; ... }`, and
nothing sets `data-theme` yet. Reason: the component stylesheets still hardcode dark colours, so an automatic light theme made the page white around dark
components and looked broken. Light stays opt-in until every component rule uses tokens.

Target end state, at the end of the component migration: the theme follows the operating system setting again (`prefers-color-scheme`, with dark as the
fallback when the browser reports no preference), or a toggle is added, and `color-scheme: dark light` is set so native controls follow. Both need
approval first (section 12). The legacy-to-token mapping for the old neon colours lives only inside the opt-in light block and is deleted with the legacy
tokens.

All text-on-background pairs below were computed (WCAG relative luminance), not estimated, and `scripts/check_contrast.py` re-checks them (section 10).
Tints are written as explicit hex tokens, not computed in CSS with `color-mix()`, so the value that was checked is the value that ships.

### 3.1 Surfaces, text, lines

| Token | Dark | Light | Notes |
|---|---|---|---|
| `--bg-root` | `#0b0e13` | `#f6f8fa` | page |
| `--bg-panel` | `#11151c` | `#ffffff` | panels |
| `--bg-panel-raised` | `#171c25` | `#f0f3f6` | panel headers, rows |
| `--bg-muted` | `#1a1f29` | `#e8ecf0` | code blocks, inputs |
| `--text-primary` | `#e6edf3` | `#1f2328` | 15.5:1 on panel (dark), 15.8:1 (light) |
| `--text-secondary` | `#a3adb9` | `#4a5560` | 8.1:1 / 7.6:1 on panel |
| `--text-muted` | `#8b96a3` | `#59636e` | 6.1:1 / 6.1:1 on panel, 5.5:1 / 5.2:1 on `--bg-muted` |
| `--border` | `#2b3542` | `#d0d7de` | decorative panel edges only (not a required boundary) |
| `--border-control` | `#6b7684` | `#848d97` | edges of buttons, inputs, toggles: 3.96:1 / 3.37:1 on panel, 4.19:1 / 3.16:1 on root |
| `--focus` | `#4fe1ff` | `#0a5c86` | 11.8:1 / 7.3:1 on panel |

Change from today: `--text-muted` was `#6b7684` (about 3.9:1 on the panel) and failed 4.5:1 for text. `#6b7684` survives only as the dark
`--border-control`. The first draft of the light `--border-control` (`#8c959f`) was 2.85:1 on the root surface; the contrast checker caught it and it is
now `#848d97`.

### 3.2 Severity (finding level)

Used for text, the badge outline and the left bar of a finding. Always paired with the visible label (section 8).

| Level | Dark | Light | Contrast on panel (dark / light) | On own 15% tint (dark / light) |
|---|---|---|---|---|
| critical | `#ff6b78` | `#b3202e` | 6.6 / 6.6 | 5.4 / 5.2 |
| high | `#ff8f60` | `#a8400f` | 8.2 / 6.2 | 6.4 / 4.9 |
| medium | `#ffb347` | `#7a4f00` | 10.3 / 7.1 | 7.6 / 5.7 |
| low | `#5cc8f0` | `#0a5c86` | 9.6 / 7.3 | 7.1 / 5.8 |
| info | `#a3adb9` | `#4a5560` | 8.1 / 7.6 | 6.2 / 6.1 |

Tokens: `--sev-critical`, `--sev-high`, `--sev-medium`, `--sev-low`, `--sev-info`, each with an explicit tint token (the colour at 15% over the panel,
written out as hex; no `color-mix()`):

| Tint token | Dark | Light |
|---|---|---|
| `--sev-critical-tint` | `#35222a` | `#f4dee0` |
| `--sev-high-tint` | `#352726` | `#f2e2db` |
| `--sev-medium-tint` | `#352d22` | `#ebe5d9` |
| `--sev-low-tint` | `#1c303c` | `#dae7ed` |
| `--sev-info-tint` | `#272c34` | `#e4e6e7` |

Near-identical pair: Low and the Needs analyst tier (3.3) have almost the same luminance (dark: 0.499 and 0.428, 1.15:1 between them; light: 0.094 and
0.087, 1.06:1). A reader cannot tell them apart by lightness, and in greyscale or with some colour-vision differences not by hue either. Rule: Low severity
and the Needs analyst tier must never appear next to each other without their written labels ("LOW", "Needs analyst"). The labels are never
shortened to a symbol, never hidden behind a tooltip, and never dropped to save space. The border style (dotted bar versus dashed outline, section 8) is a
second cue, not a replacement for the words.

### 3.3 Verdict tiers (labels per D21; the verdict card of step 13 uses them)

| Tier (UI label) | Internal key (`verdict_v2.tier`) | Token | Dark | Light | On panel (dark / light) | On 15% tint (dark / light) |
|---|---|---|---|---|---|---|
| Confirmed malicious | `confirmed_malicious` | `--verdict-malicious` | `#ff6b78` | `#b3202e` | 6.6 / 6.6 | 5.4 / 5.2 |
| Suspicious | `suspicious` | `--verdict-suspicious` | `#ffb347` | `#7a4f00` | 10.3 / 7.1 | 7.6 / 5.7 |
| Needs analyst | `needs_analyst` | `--verdict-inconclusive` | `#7fb0ff` | `#1d4fa8` | 8.3 / 7.7 | 6.4 / 6.1 |
| No indicators found | `no_indicators_found` | `--verdict-none-found` | `#a3adb9` | `#4a5560` | 8.1 / 7.6 | 6.2 / 6.1 |

**The labels changed, the internal keys and the token names did not.** Only the visible wording is new (Confirmed malicious, Suspicious, Needs analyst, No indicators found). The token names keep their
old spelling, so the tier maps to a token as: `confirmed_malicious` to `--verdict-malicious`, `suspicious` to `--verdict-suspicious`, `needs_analyst` to `--verdict-inconclusive`,
`no_indicators_found` to `--verdict-none-found`. The v1 values (`malicious`, `suspicious`, `inconclusive`, `benign`) are frozen API values and are never shown once `verdict_v2` is present (V13).

Tokens: `--verdict-malicious`, `--verdict-suspicious`, `--verdict-inconclusive`, `--verdict-none-found`, each with an explicit tint token. The last
colour is the same neutral grey as `--text-secondary` on purpose.

| Tint token | Dark | Light |
|---|---|---|
| `--verdict-malicious-tint` | `#35222a` | `#f4dee0` |
| `--verdict-suspicious-tint` | `#352d22` | `#ebe5d9` |
| `--verdict-inconclusive-tint` | `#222c3e` | `#dde5f2` |
| `--verdict-none-found-tint` | `#272c34` | `#e4e6e7` |
 The existing `--verdict-needs-review` and `--verdict-legit` tokens are retired; `--verdict-legit` in particular must not
survive, because its green says "safe".

### 3.4 Other semantic tokens

- `--notice` (unavailable, error, not looked up): reuse the medium amber from 3.2 for text and border, always with the words "Unavailable", "Error" or
  "Not looked up". Amber means "attention", not "bad".
- Informational chip and trusted-hop marker: neutral (`--text-secondary` outline) plus the words ("info", "trusted receiver"). The focus colour is not reused
  for them, so the cyan or deep blue of `--focus` means "keyboard focus is here" and nothing else.
- Green is removed from the palette for status. Today `--accent-green` is used for "ok" module status, the LLM badge and the feedback-saved line. A module
  that ran without error gets neutral styling and the word "ran" (not "ok"), because a green "ok" next to "No indicators found" reads as a pass. The
  feedback-saved line becomes neutral text. The LLM opinion card gets a neutral raised surface, a dashed border and the label "AI opinion, not a verdict"
  (no green tint).

## 4. Type scale

System fonts only. No `@font-face` pointing at the network, no `@import`.

```
--font-ui:   system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Noto Sans Hebrew", "Arial Hebrew", Arial, sans-serif;
--font-mono: ui-monospace, "Cascadia Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
```

Rule: `--font-mono` is for machine tokens ONLY: email addresses, hostnames and domains, URLs (defanged), hashes, IP addresses, message and header
identifiers, and raw header lines. Everything a person reads as language uses `--font-ui` with `dir="auto"`: the subject, display names, body text, link
text shown to the reader, filenames shown as names, finding titles and descriptions, and all interface labels. Where a field holds both (a display name
next to its address), each part gets its own element and its own font.

Why: the monospace faces on the stack (Cascadia Mono, Consolas, and the generic `monospace`) have no complete Hebrew coverage. For Hebrew text the browser
falls back to some other installed font glyph by glyph, which gives uneven widths, mismatched stroke weight and, in mixed Hebrew and Latin text, a
ragged line that is harder to read and easier to misread. `--font-ui` lists Hebrew-capable system families (`Segoe UI`, `Noto Sans Hebrew`, `Arial
Hebrew`, `Arial`) so the fallback is chosen on purpose. Machine tokens are almost always ASCII, so mono costs nothing there and keeps look-alike characters
(`l`, `1`, `I`, `0`, `O`) distinguishable. `dir="auto"` stays on both kinds of element (an address is still message content).

The current app sets mono on `body`; the proposal moves mono to machine-token elements only. Font names already listed in `theme.css` that are not
bundled (`JetBrains Mono`, `Fira Code`) are dropped from the stack so the result is the same on every machine.

| Token | Size | Line height | Weight | Use |
|---|---|---|---|---|
| `--text-xs` | 0.75rem (12px) | 1.35 | 400, 600 for labels | badges, panel micro-labels, "Why" style headings (uppercase, 0.04em tracking) |
| `--text-sm` | 0.8125rem (13px) | 1.4 | 400 | secondary lines, evidence values, table cells |
| `--text-base` | 0.875rem (14px) | 1.45 | 400 | default body in the workbench |
| `--text-md` | 1rem (16px) | 1.4 | 600 | panel titles |
| `--text-lg` | 1.125rem (18px) | 1.3 | 600 | page and section titles |
| `--text-xl` | 1.375rem (22px) | 1.25 | 700 | the verdict label (reserved) |

Floor: no text below 12px. Line height stays at 1.35 or more because Hebrew needs more leading than Latin. Use `rem`, so browser zoom and text-size
settings work. Numerals in tables: `font-variant-numeric: tabular-nums`.

## 5. Spacing, radius, borders

Dense scale (the skill's density dial 8 maps to an 8 to 32px working range; the 2px step is added for row padding and badge padding).

| Token | Value |
|---|---|
| `--space-0` | 2px |
| `--space-1` | 4px |
| `--space-2` | 8px |
| `--space-3` | 12px |
| `--space-4` | 16px |
| `--space-5` | 24px |
| `--space-6` | 32px |

`--radius: 4px` (was 6px; tighter reads denser), `--radius-sm: 2px` for badges. Panel gap 12px (`--space-3`); panel body padding 12px; row padding
`--space-1` by `--space-3`. Page max width 1200px (was 960px) with `--space-4` side padding. Borders are 1px; the tier and severity marks in section 8 use
2 to 4px.

Interactive targets: at least 24 by 24 CSS px (WCAG 2.2 AA target size) and at least 8px between adjacent controls; buttons and toggles are 28px high.
The skill's 44pt/48dp guidance is native mobile guidance and is not used for this desktop-first tool.

## 6. Page layout and panel order

Single column, desktop first, readable at 375px wide with no horizontal page scroll (long values wrap with `overflow-wrap: anywhere`; code blocks scroll
inside their own box). Landmarks: a `header` (product name), a `main` containing everything below, panels as `section` elements with an `h2` each, so a
screen reader can jump by heading. The page header is not sticky, so nothing can cover a focused control; if anything sticky is ever added, set
`scroll-padding-top` to its height.

Order (this is the current order in `ResultsView.tsx`; it does not change):

1. Verdict slot (reserved, Phase B): tier label, score, the "not a safety verdict" sentence for the neutral tier, the reasons list.
2. Findings by signal family.
3. Coverage slot (reserved, Phase B): what was and was not checked, the blockers.
4. Sender and path (hop timeline).
5. Links (defanged text).
6. Attachments.
7. Body.
8. Images (metadata only, nothing is loaded).
9. Indicators (the only place with real links).
10. Detail by module.
11. Raw headers.
12. AI opinion (secondary, labelled, never above the verdict).
13. Feedback.
14. "Analyze another email".

Reserved slots: slots 1 and 3 get a fixed container with the panel styles and the tier styles from section 8 and nothing else. Their inner content stays as
it is today until Phase B.

Decision (was an open question): the blockers block sits INSIDE the verdict slot (slot 1), directly under the tier label, above the reasons list. For every
tier the order inside slot 1 is: tier label and score, blockers block, the "not a safety verdict" sentence (neutral tier only, in the same position for
that tier), reasons, top drivers. The neutral tier therefore can never be seen without its blockers, however far down the page the reader scrolls. The
coverage panel (slot 3) stays where it is as the full per-check list; slot 1 holds the blockers, meaning the checks that were not done or not conclusive
and that limit what the tier means. Phase B decides the exact contents and wording of both, and how the two avoid repeating each other. This document only
fixes the position: in the verdict container, right under the label, always rendered (with an explicit "none" line when there are no blockers, so its
absence is never mistaken for a missing block).

Inside a panel, multi-part content uses the existing responsive grid (`repeat(auto-fit, minmax(280px, 1fr))`), so wide screens use two or three columns
without a separate layout mode. A side rail or tab layout was considered and rejected for now (section 11).

## 7. Component styles

All components use tokens only (no raw hex in component rules).

- Panel: `--bg-panel`, 1px `--border`, `--radius`, collapsible panels have a header that is a real `<button>` with `aria-expanded`, full width, `--bg-panel-raised`,
  28px minimum height, a text caret ("+" or "-" as text, or a CSS-drawn chevron; no icon package, no image).
- Panel header status chip: text label plus outline (see badge). Module that ran without error: neutral chip "ran". Module error: amber chip "error".
- Row (list item): `--bg-panel-raised`, 1px `--border`, `--space-1` by `--space-3` padding, 8px gap between rows.
- Evidence key/value: `dt` in `--text-muted` and `--font-ui`; `dd` in `--text-primary`, `--font-mono` when the value is a machine token and `--font-ui`
  when it is human language (a subject, a display name, body text, link text shown to the reader). All `dd` have `dir="auto"`, `overflow-wrap: anywhere`,
  `text-align: start`.
- Badge: `--text-xs`, 600, uppercase for fixed words only (never uppercase message text), `--radius-sm`, 1px border in its colour, text in its colour on
  `--bg-panel`, `white-space: nowrap`. Always contains a word.
- Buttons: neutral. Default: `--bg-muted`, 1px `--border-control`, `--text-primary`, 28px high. Primary (one per view, e.g. "Analyze"): `--text-primary` border
  2px, bold label; no brand colour fill. Hover (all buttons and toggles): the border goes from `--border-control` to `--text-secondary` and the
  background from `--bg-muted` to `--bg-panel-raised`. No hue change, and the `--focus` colour is never used for hover, so a hovered control cannot be mistaken for a
  keyboard-focused one. Disabled: 60% opacity plus `not-allowed`, and the label text still readable at
  4.5:1 or marked with `aria-disabled` and a visible reason.
- Form controls (file input, textarea): `--bg-muted`, 1px `--border-control`, visible label above (never placeholder-only), error text next to the control.
- Raw header blocks and other code-like blocks (machine text only; the message body is NOT one, it is human language and uses `--font-ui`, `--text-base`,
  `white-space: pre-wrap`, `dir="auto"`): `--font-mono`, `--text-sm`, `--bg-muted`, 1px `--border`, `white-space: pre-wrap`, `overflow-wrap: anywhere`, max height with its own
  scroll, `tabindex="0"` so the scroll area is keyboard reachable, `dir="auto"` on content.
- Table: header cells `--text-xs` uppercase `--text-secondary`, row separators `--border`, no zebra stripes, cell padding `--space-1` by `--space-2`.
- Timeline (hops): 2px `--border` rail; node marker is a 8px dot plus the hop role in words ("origin", "trusted receiver"), never the dot colour alone.
- Defanged values (machine tokens): shown in `--font-mono` with no underline, no link colour, no pointer cursor, so they cannot be mistaken for links. The third-party
  lookup links in the indicators panel are the only elements underlined, each followed by the visible words "opens third-party site".
- Copy buttons: the "Copied" state is plain text next to the button in a `role="status"` element (announced once), no animation.
- Focus (all interactive elements): `outline: 2px solid var(--focus); outline-offset: 2px;` via `:focus-visible`, never `outline: none` without replacement.
  The focus ring must not be clipped by `overflow: hidden` on a panel: use `outline-offset: -2px` inside clipped headers.
- Cursor: `cursor: pointer` on buttons and real links only.
- Motion: none by default. At most `transition: border-color 100ms, background-color 100ms` on hover; inside
  `@media (prefers-reduced-motion: reduce)` all transitions are `none`. No entrance, scroll or loading animation. The progress view shows text status.

## 8. Telling severity and verdict tiers apart without colour

Every distinction below survives greyscale and colour blindness, because each tier and level differs in at least three of: a written label, a
border style, a border weight, and a fill.

### 8.1 Severity (finding level), a bar on the left of the finding plus a badge

| Level | Visible label | Left bar | Badge |
|---|---|---|---|
| critical | CRITICAL | 4px solid | filled (background is the level colour, text is `--bg-root`) |
| high | HIGH | 3px solid | outlined, bold |
| medium | MEDIUM | 3px dashed | outlined |
| low | LOW | 2px dotted | outlined, regular weight |
| info | INFO | 1px solid, `--border` | no outline, text only |

Findings keep their existing sort order (most severe first) so position carries the same information. The label is real text inside the badge, so a
screen reader reads it. The bar uses `border-inline-start` so it sits on the correct side for right-to-left content.

### 8.2 Verdict tiers

| Tier | Visible label | Outline | Header band |
|---|---|---|---|
| Confirmed malicious | Confirmed malicious | 4px solid | filled: tier colour background, `--bg-root` text |
| Suspicious | Suspicious | 3px solid | tier tint token, tier colour text |
| Needs analyst | Needs analyst | 2px dashed | tier tint token, tier colour text |
| No indicators found | No indicators found | 1px dotted `--border-control` | none; `--bg-muted`, secondary text |

The neutral tier has these extra rules, which are part of its style, not optional content:

- No green, no check mark, no shield, no "OK" or "clean" wording, no tint stronger than neutral grey.
- The sentence "This is a statement about what was and was not found, not a safety verdict" is rendered inside the same container, directly under the label,
  in `--text-primary` (not muted), and so is the blockers block (what was not checked). The container has a reserved place for both so they cannot be
  dropped by a later change.
- Never visually quieter than "Needs analyst": the neutral tier uses the same size and weight for its label, only the colour and band differ.

### 8.3 Forced colors (Windows high contrast and similar modes)

In `forced-colors: active` the browser replaces our colours with the user's system palette and drops background colours, so every tint, fill and hue in
this document disappears. The marks that survive are the ones that do not depend on colour: the written labels, border style, border weight and the
outline. That is why section 8 specifies marks of that kind, and the rules below keep them visible. Use system colour keywords only (no hex), never use
`forced-color-adjust: none`, and keep the block at the end of the stylesheet that defines the component.

```
@media (forced-colors: active) {
  /* Panels, rows, badges, inputs: keep a visible edge in a system colour. */
  .panel, .row, .badge, .tier, textarea, input { border-color: CanvasText; }

  /* Severity bars keep their width and style (4px solid, 3px solid, 3px dashed, 2px dotted, 1px solid); only the colour is forced. */
  .finding[class*="sev-"] { border-inline-start-color: CanvasText; }
  /* The filled critical badge loses its fill, so it becomes a double 4px frame; the other levels stay single-line outlines. */
  .badge--critical { background: Canvas; color: CanvasText; border: 4px double CanvasText; }

  /* Tiers: outline style and weight are kept; the filled Confirmed malicious band becomes a 4px double rule under the label. */
  .tier { border-color: CanvasText; }
  .tier--malicious .tier-band { background: Canvas; color: CanvasText; border-bottom: 4px double CanvasText; }

  /* Timeline markers are background-only dots: give them a border so they still show. */
  .hop::before { background: Canvas; border: 2px solid CanvasText; }

  /* Focus ring: system highlight colour, thicker than any border, still offset (inside clipped headers use offset -3px). */
  :focus-visible { outline: 3px solid Highlight; outline-offset: 2px; }

  /* Hover: width change only, no colour (a forced palette has no spare hue). Padding shrinks by 1px so nothing moves. */
  button:hover:not(:disabled) { border-width: 2px; padding: calc(var(--space-2) - 1px) calc(var(--space-4) - 1px); }
}
```

Disabled controls and the real lookup links take `GrayText` and `LinkText` from the browser; do not override them. The class names above are
placeholders for whatever the components are called when this is implemented. The checker script cannot test forced colors; the manual check is in
section 10.

## 9. Right-to-left and mixed text

- `dir="auto"` stays on every element that can contain message content: subjects, display names, addresses, bodies, headers, evidence values,
  indicator values, reason text built from findings, filenames.
- Chrome (labels, headings, buttons) stays left-to-right; only content follows its own direction.
- Use logical CSS properties (`margin-inline`, `padding-inline`, `border-inline-start`, `text-align: start`, `inset-inline-start`) for anything that
  sits next to content. Replace `border-left` on findings and `padding-left` on lists accordingly during implementation.
- Do not force `dir="ltr"` on addresses, hosts or hashes. They are content; `dir="auto"` stays.
- Add one Hebrew sample to a component test per touched component, as `bidi.test.tsx` already does.

## 10. Accessibility checklist for every implementation step

- Text 4.5:1, large text and UI boundaries 3:1 (tokens above are verified; recompute if a token changes). Run
  `backend/.venv/Scripts/python.exe scripts/check_contrast.py`: it checks body, secondary and muted text on the panel, root, raised and muted surfaces,
  every severity and tier colour on the panel and on its tint token, the filled-badge text, and the focus ring and control border at 3:1, in both themes.
  It reads the tokens from the table at the top of the script until they exist in `frontend/src/theme.css`, then from `theme.css`.
- Forced colors: with `forced-colors: active` (in a browser, Windows Settings, Accessibility, Contrast themes, or the DevTools "Emulate CSS media feature
  forced-colors" switch) check that panel borders, severity bars and badges, tier outlines and the focus ring are all visible, that the tier and severity
  labels are readable, and that no information was carried only by a background. The `@media (forced-colors: active)` rules in 8.3 are part of the
  implementation of every component that has a mark.
- Hover is never the focus colour: a hovered control and a keyboard-focused control must look different.
- Every control reachable and operable by keyboard, in visual order; toggles are `<button>` elements with `aria-expanded`; no hover-only information.
- `:focus-visible` ring on everything interactive, never fully hidden (no sticky overlay without `scroll-padding`).
- Meaning is always also in words (tier label, severity label, "error", "ran", "not looked up").
- Status changes that appear after load (copy state, feedback saved) use a single `role="status"` message with a full sentence, not a bare number.
- `prefers-reduced-motion` honoured; no animation to remove in the first place.
- Checked at 375px, 768px, 1024px and 1440px wide: no horizontal page scroll, no clipped focus ring.
- Screen-reader check: heading order is h1 (page), h2 (panel), h3 (group inside a panel).

## 11. What the skill recommended: adopted and rejected

Searches run (all through `.claude/skills/ui-ux-pro-max/scripts/search.py`, terminal only, no `--persist`, `--force` or `--motion`):

1. `security analyst dashboard dense data evidence` with `--design-system --density 8 --variance 2`
2. `keyboard focus visible contrast` with `--domain ux`
3. `semantic status colors dark mode severity` with `--domain color`
4. `monospace data technical dashboard` with `--domain typography`
5. `not color alone status badge` with `--domain ux`
6. `reduced motion animation` with `--domain ux`
7. `dense list table collapsible panels` with `--stack react`
8. `touch target size spacing` with `--domain ux`
9. `dark mode light mode contrast text` with `--domain ux`

No chart search was run: the workbench has no charts.

Adopted:
- Style direction "Minimalism and Swiss": functional, grid-based, high contrast, sharp edges, dashboard and professional tool fit. Taken as a direction;
  its "spacious, white space" keyword is overridden by the density dial.
- Dense dashboard spacing range (8 to 32px) and low variance (centred, minimal, no decorative layout).
- Contrast 4.5:1 for text, visible focus ring on every control, focus not obscured (WCAG 2.2 AA), reduced-motion media query.
- "Color only" rule: information is also text. This drives section 8.
- WCAG 2.2 target size (24 CSS px minimum) with 8px spacing, instead of the native 44/48 values.
- "Excessive motion": fewer than two animated elements per view; here the answer is zero.
- Duration guidance: not one universal duration; here only a 100ms colour change on hover, removed under reduced motion.
- Atomic `role="status"` message for async state, and no emoji as icons.
- Stable keys in lists (already done in the code).
- Mono for machine tokens and sans for everything a person reads (the idea behind the "Dashboard Data" pairing), implemented with system fonts only.
- Light and dark both supported (the skill's style lists both).

Rejected, with the reason:
- Pattern "Enterprise Gateway" (hero, solutions by industry, client logos, contact sales): a marketing landing page. This is a workbench.
- Palette #1E40AF primary, #D97706 accent/CTA, #F8FAFC background: brand and call-to-action colour has no role here, and an accent-coloured primary
  button would compete with the severity colours. Buttons stay neutral.
- The green-accent palettes returned for the dark dashboard queries (#22C55E): green reads as "safe" and is forbidden for the neutral tier; green is
  removed from status colour in section 3.4.
- Google Fonts pairing (Fira Code and Fira Sans), its `@import url(https://fonts.googleapis.com ...)` and the other Google Fonts URLs shown: remote fonts
  are forbidden and the rendering-rules test fails on a remote `@import`. System stack instead.
- "Terminal CLI Monospace" notes (one mono family for everything, sizes 12/14/16 only, weight 400 only, line height 1.2): weight 400 only removes the
  hierarchy a dense page needs, and 1.2 line height is too tight for Hebrew. Mono is limited to machine tokens.
- Skill guideline "base 16px body, line height 1.5": too sparse for this density. Base is 14px with a 12px floor and a 1.35+ line height.
- Skill suggestion of SVG icon sets (Heroicons, Lucide) and any Tailwind config lines: a new dependency, and Tailwind is not in this repo. Text labels and
  CSS-drawn shapes only.
- GSAP presets, `--motion` dial, "hover 150 to 300ms" transitions, "single hero animation": decorative motion is excluded by the brief.
- Mobile-native touch rules (44pt, 48dp, bottom navigation, safe areas): not applicable to a desktop analyst page; web target-size rule used instead.
- Generic React results (generics for list components, compound components, `key` rules): not design guidance for this task, only stable keys noted.
- Skill pre-delivery items about alt text, hero imagery and landing structure: there are no images and no landing page.
- Persisted `design-system/` folder (MASTER.md and page overrides): not created; this file is the single source of truth.

Not verified: the ASCII design-system output did not print the `--space-*` table the density dial is documented to produce, so the spacing scale in
section 5 is derived from the documented 8 to 32px range, not copied from a tool result.

## 12. Implementation notes for later steps (not done here)

- Keep three stylesheets (`theme.css` tokens, `app.css` shell and summary, `workbench.css` evidence panels). Put every new token in `theme.css`. The
  existing test asserts `app.css` contains `.verdict-benign` and that at least three stylesheets exist and are not empty; do not rename or merge them.
- The tokens are in `theme.css` (dark in `:root`, light in `:root[data-theme="light"]`, tints as hex). `scripts/check_contrast.py` reads them from there
  and fails if the light block or any required token is missing, so light is checked even though nothing applies it. The checker runs in the pre-commit
  hook. Keep the light block last in the file, written exactly `:root[data-theme="light"] {`.
- Last migration step: re-enable `prefers-color-scheme` (or add a toggle that sets `data-theme`), switch `color-scheme` to `dark light`, update the
  checker's block selector if the light rule moves, and delete the legacy tokens.
- Introduce tokens first (theme.css), then migrate component rules to tokens one stylesheet at a time, running `npm test` and `npm run lint` after each.
- Tier styles from section 8.2 are wired into the verdict card and the coverage panel in step 13 (section 13).
- Any new dependency, any theme toggle and any change to panel order needs approval first.

## 13. Step 13 as built: the verdict card and the coverage panel (2026-10-07)

Source: `verdict_v2` and `checks_completed` from the API (docs/DESIGN_V2.md 2.1, 2.3, 2.4, 3, D1, D19, V13). No numeric score and no confidence percentage are shown.

**Which card renders** (`frontend/src/components/VerdictCard.tsx`):
1. The result has `verdict_v2`: the tier card. The v1 verdict (label, value, score, confidence, "Overrides applied", "Top drivers") appears nowhere on the page or in the exports (V13).
2. It has `verdict_v2_status` but no `verdict_v2`: a neutral card "Verdict unavailable" (2px dashed `--notice` outline, the word in the band) with the coverage item's reason code and its "To clear" hint, and no tier and no v1 label.
3. An OLD-shape result (neither field, such as a stored job): the old v1 card, unchanged.

**Inside the tier card, in this order:** the tier label in the band (the outline and band of 8.2: 4px solid and filled; 3px solid and tint; 2px dashed and tint; 1px dotted and neutral), the route in plain words,
the blockers block (always rendered, with an explicit "None." line), the neutral tier's sentence (No indicators found only, in `--text-primary`), the Needs analyst sub-reason and the queue priority
labelled "Queue priority (ordering aid, not a probability)" (Needs analyst only), the hard-evidence list (Confirmed malicious only: rule, source, defanged indicator), the evidence-conflict block when present,
and the reasons (the class and the severity of the finding behind each, and the finding's title the page already shows; the API's own text for a reason that rests on no finding).
The class of a finding is its family tag (sender, link, claim) or else its module (auth, enrichment, content): the rule the backend table follows.

The tier styles are the classes `.tier--malicious`, `.tier--suspicious`, `.tier--inconclusive` (Needs analyst), `.tier--none-found` and `.tier--unavailable`; the token names did not change.
Every element that can show message content has `dir="auto"`; the chrome does not. No animation. In forced-colors mode the outline weight and style stay and the filled band becomes a 4px double rule.

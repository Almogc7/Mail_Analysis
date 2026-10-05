# UI design system (proposal, text only)

Status: proposal awaiting approval. Nothing in `frontend/` has been changed by this document. It defines the target look and the rules every later
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
9. Scope: verdict card and coverage panel content are untouched until Phase B.

## 3. Colour tokens

Dark is the default (the current look, and the usual setting for a queue worked all day). Light applies under `prefers-color-scheme: light`. There is no
theme toggle in this proposal; one can be added later without changing the tokens. Set `color-scheme: dark light` so native controls follow.

All text-on-background pairs below were computed (WCAG relative luminance), not estimated.

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
| `--border-control` | `#6b7684` | `#8c959f` | edges of buttons, inputs, toggles: 3.96:1 / 3.04:1 on panel |
| `--focus` | `#4fe1ff` | `#0a5c86` | 11.8:1 / 7.3:1 on panel |

Change from today: `--text-muted` was `#6b7684` (about 3.9:1 on the panel) and failed 4.5:1 for text. `#6b7684` survives only as the dark
`--border-control`.

### 3.2 Severity (finding level)

Used for text, the badge outline and the left bar of a finding. Always paired with the visible label (section 8).

| Level | Dark | Light | Contrast on panel (dark / light) | On own 15% tint (dark / light) |
|---|---|---|---|---|
| critical | `#ff6b78` | `#b3202e` | 6.6 / 6.6 | 5.4 / 5.2 |
| high | `#ff8f60` | `#a8400f` | 8.2 / 6.2 | 6.4 / 4.9 |
| medium | `#ffb347` | `#7a4f00` | 10.3 / 7.1 | 7.6 / 5.7 |
| low | `#5cc8f0` | `#0a5c86` | 9.6 / 7.3 | 7.1 / 5.8 |
| info | `#a3adb9` | `#4a5560` | 8.1 / 7.6 | 6.2 / 6.1 |

Tokens: `--sev-critical`, `--sev-high`, `--sev-medium`, `--sev-low`, `--sev-info`. Tint token pattern:
`color-mix(in srgb, var(--sev-x) 15%, var(--bg-panel))`.

### 3.3 Verdict tiers (styles defined now, content in Phase B)

| Tier (UI label) | Internal key | Dark | Light | On panel (dark / light) | On 15% tint (dark / light) |
|---|---|---|---|---|---|
| Malicious | `malicious` | `#ff6b78` | `#b3202e` | 6.6 / 6.6 | 5.4 / 5.2 |
| Suspicious | `suspicious` | `#ffb347` | `#7a4f00` | 10.3 / 7.1 | 7.6 / 5.7 |
| Inconclusive: analyst review | `inconclusive` | `#7fb0ff` | `#1d4fa8` | 8.3 / 7.7 | 6.4 / 6.1 |
| No indicators found | `benign` | `#a3adb9` | `#4a5560` | 8.1 / 7.6 | 6.2 / 6.1 |

Tokens: `--verdict-malicious`, `--verdict-suspicious`, `--verdict-inconclusive`, `--verdict-none-found`. The last one is the same neutral grey as
`--text-secondary` on purpose. The existing `--verdict-needs-review` and `--verdict-legit` tokens are retired; `--verdict-legit` in particular must not
survive, because its green says "safe".

### 3.4 Other semantic tokens

- `--notice` (unavailable, error, not looked up): reuse the medium amber from 3.2 for text and border, always with the words "Unavailable", "Error" or
  "Not looked up". Amber means "attention", not "bad".
- `--info` (informational chip, trusted hop, link-like affordance): reuse `--focus` colour family (cyan dark, deep blue light).
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

Rule: sans (`--font-ui`) for labels, headings and prose; mono (`--font-mono`) only for values taken from the message and for code-like blocks
(addresses, hosts, hashes, header lines). The current app sets mono on `body`; the proposal moves mono to values. Reason: Hebrew and long prose are
harder to read in a mono face, and mono for values keeps look-alike characters distinguishable. Font names already listed in `theme.css` that are not
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
it is today until Phase B. Open question for Phase B (not decided here): the neutral tier must always show its blockers, so Phase B may want the blockers
inside slot 1 or slot 3 moved directly under the tier label instead of two panels down.

Inside a panel, multi-part content uses the existing responsive grid (`repeat(auto-fit, minmax(280px, 1fr))`), so wide screens use two or three columns
without a separate layout mode. A side rail or tab layout was considered and rejected for now (section 11).

## 7. Component styles

All components use tokens only (no raw hex in component rules).

- Panel: `--bg-panel`, 1px `--border`, `--radius`, collapsible panels have a header that is a real `<button>` with `aria-expanded`, full width, `--bg-panel-raised`,
  28px minimum height, a text caret ("+" or "-" as text, or a CSS-drawn chevron; no icon package, no image).
- Panel header status chip: text label plus outline (see badge). Module that ran without error: neutral chip "ran". Module error: amber chip "error".
- Row (list item): `--bg-panel-raised`, 1px `--border`, `--space-1` by `--space-3` padding, 8px gap between rows.
- Evidence key/value: `dt` in `--text-muted`, `dd` in `--text-primary` and `--font-mono`, both `dir="auto"`, `overflow-wrap: anywhere`, `text-align: start`.
- Badge: `--text-xs`, 600, uppercase for fixed words only (never uppercase message text), `--radius-sm`, 1px border in its colour, text in its colour on
  `--bg-panel`, `white-space: nowrap`. Always contains a word.
- Buttons: neutral. Default: `--bg-muted`, 1px `--border-control`, `--text-primary`, 28px high. Primary (one per view, e.g. "Analyze"): `--text-primary` border
  2px, bold label; no brand colour fill. Hover: border colour to `--focus`. Disabled: 60% opacity plus `not-allowed`, and the label text still readable at
  4.5:1 or marked with `aria-disabled` and a visible reason.
- Form controls (file input, textarea): `--bg-muted`, 1px `--border-control`, visible label above (never placeholder-only), error text next to the control.
- Code and raw blocks: `--font-mono`, `--text-sm`, `--bg-muted`, 1px `--border`, `white-space: pre-wrap`, `overflow-wrap: anywhere`, max height with its own
  scroll, `tabindex="0"` so the scroll area is keyboard reachable, `dir="auto"` on content.
- Table: header cells `--text-xs` uppercase `--text-secondary`, row separators `--border`, no zebra stripes, cell padding `--space-1` by `--space-2`.
- Timeline (hops): 2px `--border` rail; node marker is a 8px dot plus the hop role in words ("origin", "trusted receiver"), never the dot colour alone.
- Defanged values: shown in `--font-mono` with no underline, no link colour, no pointer cursor, so they cannot be mistaken for links. The third-party
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

### 8.2 Verdict tiers (styles only; wording and content are Phase B)

| Tier | Visible label | Outline | Header band |
|---|---|---|---|
| Malicious | Malicious | 4px solid | filled: tier colour background, `--bg-root` text |
| Suspicious | Suspicious | 3px solid | 15% tint, tier colour text |
| Inconclusive: analyst review | Inconclusive: analyst review | 2px dashed | 15% tint, tier colour text |
| No indicators found | No indicators found | 1px dotted `--border-control` | none; `--bg-muted`, secondary text |

The neutral tier has these extra rules, which are part of its style, not optional content:

- No green, no check mark, no shield, no "OK" or "clean" wording, no tint stronger than neutral grey.
- The sentence "This is a statement about what was and was not found, not a safety verdict" is rendered inside the same container, directly under the label,
  in `--text-primary` (not muted), and so is the blockers block (what was not checked). The container has a reserved place for both so they cannot be
  dropped by a later change.
- Never visually quieter than "Inconclusive": the neutral tier uses the same size and weight for its label, only the colour and band differ.

## 9. Right-to-left and mixed text

- `dir="auto"` stays on every element that can contain message content: subjects, display names, addresses, bodies, headers, evidence values,
  indicator values, reason text built from findings, filenames.
- Chrome (labels, headings, buttons) stays left-to-right; only content follows its own direction.
- Use logical CSS properties (`margin-inline`, `padding-inline`, `border-inline-start`, `text-align: start`, `inset-inline-start`) for anything that
  sits next to content. Replace `border-left` on findings and `padding-left` on lists accordingly during implementation.
- Do not force `dir="ltr"` on addresses, hosts or hashes. They are content; `dir="auto"` stays.
- Add one Hebrew sample to a component test per touched component, as `bidi.test.tsx` already does.

## 10. Accessibility checklist for every implementation step

- Text 4.5:1, large text and UI boundaries 3:1 (tokens above are verified; recompute if a token changes).
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
- Mono for data and sans for labels (the idea behind the "Dashboard Data" pairing), implemented with system fonts only.
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
  hierarchy a dense page needs, and 1.2 line height is too tight for Hebrew. Mono is limited to values.
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
- Introduce tokens first (theme.css), then migrate component rules to tokens one stylesheet at a time, running `npm test` and `npm run lint` after each.
- Tier styles from section 8.2 are added as CSS classes now but are only wired into the verdict and coverage markup in Phase B.
- Any new dependency, any theme toggle and any change to panel order needs approval first.

# Design review — NKS WDC Catalog admin, 2026-04-17

## 1. Verdict

The admin feels "dark and low-contrast" in light mode not because the palette is literally dark — `#fbfcfd` bg, `#0b1220` text — but because the entire surface is **monochromatic slate with a single cold indigo accent**, starved of hierarchy, warmth, and rhythm. Every card, pill, header, input and table frame shares the same 1 px `#d1d5db` border and the same `--shadow-sm`. Nothing visually dominates, so the eye reads the page as a flat grey grid — which the brain files as "dim." Bumping `--text-3` to `#334155` fixed WCAG but did not fix the *perceived* contrast problem: **contrast of hierarchy, not of pixels**.

## 2. Concrete problems (by screenshot)

- **01-login.png** — Login card is a white rectangle on off-white with a grey border. Nothing to look at. Login is a 50 ms credibility judgement (Lindgaard 2006); this one says "intranet."
- **13/21/23/25 dashboard variants** — Stat cards are all equal weight. `.stat-card h3` (uppercase `0.714rem`, `--text-3`) is *louder* than the number beneath it — the KPI is not the hero. Sparkline at 40 px in accent on white looks like a logo afterthought.
- **04/11/27 tables** — Tables use 12 px font with identical 1 px borders per row and no zebra. At ≥20 rows the table becomes a grey grid (NN/g "Data Tables" 2019: zebra or row-hover beats borders every time). `thead th` uppercase 10 px is below the comfortable reading floor.
- **14/15/16/26 details** — `.meta` and `.action-grid` sit side-by-side with identical padding, radius, and border. Nothing says "identity block vs actions row." Five containers on one page, all the same.
- **08 retention** — `form-grid auto-fit` crams retention policy inputs into 4 columns with no grouping. Two unrelated numbers end up adjacent.
- **Dark mode (26)** — `--border: rgba(255,255,255,0.09)` is invisible on `--surface #151820`. Cards dissolve into the bg.
- **Mobile** — `.nav` scrolls horizontally with hidden scrollbar. Active tab can be off-screen.

## 3. Design direction

### 3.1 Palette — introduce warmth + split the accent

Indigo `#4f46e5` on `#fbfcfd` slate is the "generic SaaS" signature. Move neutrals one step warmer, keep indigo but demote it to *interactive-only*, introduce a **paper/ink pair** so the eye has somewhere to rest.

Proposed tokens (light):
- `--bg`: `#fbfcfd` → `#f5f3ee` (warm paper)
- `--surface-2`: `#f3f4f7` → `#ebe7de`
- `--border`: `#d1d5db` → `#d9d3c6` — reserve borders for inputs + dividers, shadow for card edges
- `--text`: `#0b1220` → `#1a1a1a` (neutral black reads warmer)
- Split `--accent` into `--ink #1f3a5f` (structural/brand) + `--action #c2410c` or `#0f766e` (CTA). Two-color system is what Linear, Stripe, Resend share.

Dark: lift `--surface` to `#1a1d24`, `--border` to `rgba(255,255,255,0.14)` minimum, double-layer edge shadow `0 2px 12px rgba(0,0,0,.55), 0 0 0 1px rgba(255,255,255,.06)`.

### 3.2 Typography — one distinctive move, not five safe ones

- **Headings**: Geist, Space Grotesk, or Inter Tight — weights 500/700 only, dramatic jumps.
- **Mono (numbers, IDs, tokens)**: JetBrains Mono / Geist Mono + `font-variant-numeric: tabular-nums` on every numeric cell. Makes the whole app look designed.
- **Size scale**: base 15 px (was 14). Drop uppercase + 0.05em on form labels; modern admin uses sentence-case.

### 3.3 Three-tier elevation hierarchy

- Hero containers (stat cards, login): padding 28 px, shadow, no border.
- List containers (tables, meta): padding 12–16, 1 px border, no shadow.
- Chrome (topbar, footer): padding 0/16, hairline only.

This is the hierarchy layer that is currently missing.

### 3.4 Tables — biggest perceived-quality win

- Zebra rows `.data tbody tr:nth-child(even)`, remove per-row borders.
- Row height 44 px, `line-height: 1.5`.
- Right-align numeric columns + mono + tabular-nums.
- Drop uppercase on `thead th`, use 12 px semibold + `border-bottom: 2px solid var(--text-3)` only under header row.
- Hover: `box-shadow: inset 3px 0 0 var(--accent)` — left-edge indicator.
- Empty state: icon + copy + CTA, not italic grey text.

### 3.5 Dashboard — make KPIs the KPIs

One hero card full-width first row (2.5rem mono KPI, 64 px sparkline with area fill), supporting stats in 3-col grid beneath with delta (+4 green / −2 red).

### 3.6 Forms — grouping beats auto-fit

Retention + Settings are configuration surfaces. Use fieldset-cards per concern, 2-col grid inside, helper text below input (not uppercase label). Primary button bottom-right, secondary left (Gestalt).

### 3.7 Error + empty states

404 needs a second line with path/trace id. Empty tables get icon + cause + CTA.

### 3.8 Dark mode must not be an inversion

Four-step ladder: `#11131a → #1a1d24 → #22262f → #2a2f39`. Borders `rgba(255,255,255,0.14)` min. `--text-3` on dark surface currently fails AA.

### 3.9 Mobile

`.nav` overflow → fade gradient + arrows, or drawer below 720 px. `.section-head` buttons need right-align wrap.

## 4. Already working

- Role pill color ladder (readonly → owner) — distinct hues, right loudness curve.
- Semantic success/warning/danger tokens with paired bg/border — keep, just warm ~5° toward new paper.
- Sticky `.data thead th` — correct.
- CSS variable architecture is clean; this is a token reskin, not a rewrite.

## 5. Prioritized punch list

### P0

1. **Palette swap**: warm paper + split ink/action accent.
2. **Typography**: Geist/Space Grotesk headings, JetBrains Mono for numerics, base 15 px, drop uppercase labels.
3. **Table redesign**: zebra, no per-row borders, 2 px header underline, tabular-nums, 44 px rows, left-edge hover indicator.
4. **Elevation hierarchy**: shadow-on-card vs border-on-list separation.
5. **Dark-mode borders & text**: `--border rgba(255,255,255,.14)`, `--text-3 #a0a6c0`, `--surface #1a1d24`.

### P1

6. Dashboard hero card + area-fill sparkline at 64 px.
7. Form grouping via fieldset-cards with 2-col inner grid + helper text.
8. PAT/invite success states: hero token block with copy button.
9. Empty states for tables (icon + copy + CTA).
10. Numeric columns right-aligned + tabular-nums everywhere.

### P2

11. Login brand moment (logomark + warm gradient).
12. Mobile drawer nav <720 px.
13. `prefers-reduced-motion` guard.
14. Active chip state (filled accent, not just hover).
15. Audit log JSON details with syntax-tinted keys.

## 6. If you only do one thing

**P0 #1 + #3 together**: warm neutrals + restyled tables. Converts the two surfaces the user stares at most (dashboard + audit/users) from "gray intranet" to "considered product" without touching a template.

## 7. Sources

- NN/g, "Horizontal Attention Leans Left" (2024)
- NN/g, "F-Shaped Pattern of Reading" (2024 re-run)
- NN/g, "Data Table Design Best Practices" (2019)
- NN/g, "Visual Hierarchy in UX Design" (2020)
- NN/g, "Empty States" (2021)
- Lindgaard et al., "You have 50 milliseconds" (Behaviour & IT, 2006)
- Hoober, "How Do Users Really Hold Mobile Devices?" (UXmatters, 2023)
- WCAG 2.2 SC 1.4.3 — contrast minima

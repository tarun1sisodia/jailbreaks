# Product Requirements Document (PRD) v2.0
## WebProbe UI — Web Security Scanner & Assessment Dashboard
### **Implementation-Ready Specification**

**Document Version:** 2.0.0 (Expanded / AI-Execution Grade)  
**Status:** Locked for Implementation  
**Rule for AI Agent:** Every field, label, state, and interaction in this document is **normative**. If something is unspecified, **do not invent it** — fall back to the closest specified pattern or the "Defaults & Fallbacks" section (§11). Do not alter copy, colors, or component behavior.

---

## Table of Contents
1. How to Use This Document
2. Design Foundations (Tokens, Typography, Motion)
3. Global Application Shell
4. Reusable Component Library
5. Data Contracts (TypeScript Interfaces)
6. Route Map & Page Registry
7. Page-by-Page Specifications (All 9 Pages)
8. State Matrix (Loading / Empty / Error / Success)
9. Exact Copy Library (Normative Strings)
10. Interaction Rules (Keyboard, Focus, Toasts, Redirects)
11. Defaults, Fallbacks & Validation Rules
12. Responsive & Accessibility Requirements
13. Implementation Order Checklist

---

## 1. How to Use This Document

**For AI agent / engineer:**
1. Read §2 (tokens) and §3 (shell) first — nothing else compiles without them.
2. Build §4 (component library) before any page.
3. Define §5 (data contracts) as TypeScript types in `types/` before writing fetch calls.
4. Build pages in the exact order in §13.
5. Every page in §7 has: **Purpose · Layout · Fields · States · Interactions · API Calls · Exact Copy**. Treat each as a checklist.
6. Any UI string in **`backticks`** is literal and must appear exactly as written.
7. Any color/hex/px is exact, not a suggestion.

**Explicitly forbidden:** Placeholder pages, lorem ipsum, invented extra fields, invented button labels, invented routes, gradient-heavy "AI design" aesthetics. Follow the Vercel/Linear/Raycast minimalism — flat cards, 1px borders, muted surfaces, emerald accent used sparingly.

---

## 2. Design Foundations

### 2.1 Color Tokens (Dark Mode = Default)

| Token | Hex | Usage |
|---|---|---|
| `--bg-base` | `#09090b` | Page background |
| `--bg-card` | `#121215` | Card / panel surface |
| `--bg-muted` | `#18181b` | Input bg, hover row |
| `--bg-elevated` | `#1c1c1f` | Dropdown / popover / drawer |
| `--border-subtle` | `#27272a` | Default 1px border |
| `--border-strong` | `#3f3f46` | Focused input border |
| `--text-primary` | `#fafafa` | Headings & body |
| `--text-muted` | `#a1a1aa` | Secondary text |
| `--text-faint` | `#71717a` | Captions, meta |
| `--accent-emerald` | `#10b981` | Primary CTA, success |
| `--accent-emerald-hover` | `#059669` | CTA hover |
| **Severity – Critical** | `#ef4444` / bg `rgba(239,68,68,0.12)` | |
| **Severity – High** | `#f97316` / bg `rgba(249,115,22,0.12)` | |
| **Severity – Medium** | `#f59e0b` / bg `rgba(245,158,11,0.12)` | |
| **Severity – Low** | `#3b82f6` / bg `rgba(59,130,246,0.12)` | |
| **Severity – Info** | `#64748b` / bg `rgba(100,116,139,0.12)` | |
| **Status – Running** | `#10b981` (pulse) | |
| **Status – Queued** | `#f59e0b` | |
| **Status – Completed** | `#3b82f6` | |
| **Status – Failed/Aborted** | `#ef4444` | |

Light mode must ship as a parallel token set (same names) — **do not skip it**, only invert base/border/text values.

### 2.2 Typography

| Role | Font | Weight | Size / Line-Height |
|---|---|---|---|
| Display (hero) | Inter | 600 | 40px / 48px |
| H1 (page title) | Inter | 600 | 28px / 36px |
| H2 (section) | Inter | 600 | 20px / 28px |
| H3 (card title) | Inter | 500 | 16px / 24px |
| Body | Inter | 400 | 14px / 22px |
| Small / meta | Inter | 400 | 12px / 18px |
| Micro (badge) | Inter | 600 | 11px / 14px, uppercase, 0.04em tracking |
| Code / mono | JetBrains Mono | 400/500 | 13px / 20px |

### 2.3 Spacing Scale
`4 · 8 · 12 · 16 · 20 · 24 · 32 · 40 · 48 · 64` (px). No arbitrary values.

### 2.4 Radius
`--radius-sm: 6px` (badges, pills) · `--radius-md: 8px` (inputs, buttons) · `--radius-lg: 12px` (cards) · `--radius-xl: 16px` (drawers, modals).

### 2.5 Shadows
Only one: `--shadow-drawer: 0 10px 40px rgba(0,0,0,0.45)`. Cards use borders, not shadows.

### 2.6 Motion
- Default transition: `150ms ease-out`.
- Drawer slide: `250ms cubic-bezier(0.32, 0.72, 0, 1)`.
- Respect `prefers-reduced-motion: reduce` → disable transforms, keep opacity fades.

### 2.7 Iconography
`lucide-react` only. Sizes: `14`, `16`, `18`, `20`, `24`. Stroke width `1.75`. Never mix icon sets.

---

## 3. Global Application Shell

### 3.1 App Layout Structure

```
<AppShell>
  <TopNav />                 // fixed, h=56px, border-bottom
  <main className="pt-14 min-h-screen">
    <PageContent />
  </main>
  <Toaster />
  <CommandPalette />         // ⌘K
</AppShell>
```

No sidebar by default. All top-level routes reachable from TopNav. Secondary routes appear as tabs *inside* a page.

### 3.2 TopNav Specification

**Height:** 56px · **Border-bottom:** 1px `--border-subtle` · **Background:** `--bg-base` with `backdrop-blur` at 8px.

**Left cluster (order):**
1. Logo icon: `ShieldCheck` (20px, `--accent-emerald`) + wordmark text `WebProbe` (Inter 600, 15px, `--text-primary`).
2. Nav links (gap 24px, 14px/500): `Dashboard` → `/` · `Scans` → `/scans` · `Catalog` → `/catalog` · `Settings` → `/settings`. Active link gets `--text-primary` + 2px emerald underline offset 14px. Inactive = `--text-muted`.

**Right cluster (order, gap 12px):**
1. Backend status pill: `[dot] Connected · v3.0.0` / `[dot] Offline`. Green pulse dot when healthy, red static when offline. Clicking opens a small popover showing `GET /health` JSON (mono).
2. Command palette trigger: `Search… ⌘K` button (ghost, muted).
3. Theme toggle: `Sun` / `Moon` icon button.
4. Avatar placeholder: 28px circle, initials from localStorage user name or `WP`.

**Mobile (<768px):** Collapse nav links into a `Menu` hamburger that opens a full-width dropdown sheet. Right cluster shows only status dot + hamburger.

### 3.3 Footer (only on Dashboard and Settings)
1px top border, 48px height, flex between:
- Left: `WebProbe v2.0.0 · Engine 3.0.0`
- Right: `Documentation` · `API Reference` · `Changelog` (all `--text-muted`, 12px).

### 3.4 Toast System
Position bottom-right, stack up to 4, auto-dismiss 5s (error 8s). Variants: `success`, `error`, `info`, `warning`. Each has icon + title (14px/600) + description (13px/400) + close X. Matches §9 copy.

### 3.5 Command Palette (⌘K / Ctrl+K)
Modal overlay (`--bg-elevated`, radius 12, width 560, top-offset 20vh). Input + grouped results:
- **Navigate:** Dashboard, Scans, Catalog, Settings, New Scan
- **Actions:** Start Quick Scan, Toggle Theme, Copy API URL
Fuzzy filter, arrow-key nav, Enter to select, Esc to close. Empty state: `No results for "{query}"`.

---

## 4. Reusable Component Library

Every page composes from these. Each is specified with props + all variants.

### 4.1 `<Button>`
Props: `variant` (`primary` | `secondary` | `ghost` | `danger` | `link`), `size` (`sm` 32px / `md` 36px / `lg` 44px), `loading: boolean`, `disabled: boolean`, `iconLeft`, `iconRight`, `fullWidth`.
- **primary:** emerald bg, white text, hover `--accent-emerald-hover`.
- **secondary:** transparent bg, 1px `--border-subtle`, `--text-primary`, hover `--bg-muted`.
- **ghost:** transparent, `--text-muted`, hover `--bg-muted`.
- **danger:** red bg (`#ef4444`), white text.
- **link:** no bg, `--accent-emerald`, underline on hover.
- **loading:** spinner replaces left icon, text remains, pointer disabled.

### 4.2 `<Input>`
Props: `label` (14px/500, `--text-primary`, mb 6), `placeholder`, `hint` (12px, `--text-faint`), `error` (12px, `#ef4444`), `prefix` (icon), `suffix`, `disabled`, `type`.
Height 36px, radius 8px, bg `--bg-muted`, border 1px `--border-subtle`, focus → border `--border-strong` + 1px emerald ring at 0 opacity → `0.3`.

### 4.3 `<Select>` (shadcn)
Native-accessible listbox. Height 36px, same visual as Input. Options show label + optional meta on right.

### 4.4 `<Toggle>` (switch)
Width 36 × height 20. Off: `--bg-muted` + `--border-subtle`. On: `--accent-emerald`. Knob white, 16px. Label appears to the **left** of the toggle (14px/500) with a 12px description under the label.

### 4.5 `<Slider>`
Track 4px, `--bg-muted`. Fill `--accent-emerald`. Knob 16px circle white with 1px border. Right-side numeric display of current value (mono, 13px) with unit.

### 4.6 `<Badge>`
`variant`: `severity-critical | severity-high | severity-medium | severity-low | severity-info | status-running | status-queued | status-completed | status-aborted | neutral | outline`.
Height 20px, px 8px, radius 6, 11px/600 uppercase. Severity variants use the §2.1 pairs.

### 4.7 `<Card>`
1px `--border-subtle`, radius 12, bg `--bg-card`, padding 20px. Optional `title`, `description`, `action` (right slot), `footer`.

### 4.8 `<MetricCard>`
Props: `label` (12px/500 uppercase, `--text-faint`), `value` (28px/600 mono), `delta?: {value, direction}`, `icon`, `tone` (neutral/good/danger). Card frame. Value animates via count-up on mount (400ms).

### 4.9 `<Table>`
Sticky header (h 40px, bg `--bg-card`, 11px/600 uppercase, `--text-muted`). Row 48px, hover `--bg-muted`, `border-b` 1px `--border-subtle`. Right-most column reserved for actions. Uses TanStack Table under the hood. Column defs pass a `header`, `cell` renderer, and optional `sortable`.

### 4.10 `<Drawer>` (right slide-over)
Width 560px desktop, full-width mobile. Backdrop `rgba(0,0,0,0.5)`. Radius 16 left corners. Header sticky (title + close X). Tabs row. Scrollable body. Footer sticky with actions. Slides in 250ms, traps focus, Esc closes.

### 4.11 `<Modal>`
Centered, width 480, radius 12, bg `--bg-elevated`, backdrop. Title (18px/600), body, footer with right-aligned buttons (secondary then primary). Max 1 modal open at a time.

### 4.12 `<Tabs>`
Underline style: 1px bottom border container, active tab has 2px `--accent-emerald` underline, text `--text-primary`. Inactive `--text-muted`. Height 40px.

### 4.13 `<CodeBlock>`
Mono font, bg `#0a0a0b`, padding 16, radius 8, border `--border-subtle`, optional language label top-right, copy button top-right (`Copy` → `Copied` for 2s). Line numbers optional via prop `showLineNumbers`.

### 4.14 `<EmptyState>`
Centered: icon (40px, `--text-faint`), title (16px/600), description (14px, `--text-muted`, max-w 400 center), optional action button.

### 4.15 `<Skeleton>`
Shimmer block, bg `--bg-muted`, radius matches target. Used in Table (rows), MetricCards (value line), CodeBlock (lines).

### 4.16 `<Terminal>`
Black (`#050505`), mono 13px, padding 16, radius 8, border `--border-subtle`. ANSI color parsing (green=success, red=error, yellow=warn, gray=debug, cyan=info). Auto-scroll toggle top-right. Search bar. Copy-all button.

### 4.17 `<SeverityBar>`
Horizontal stacked bar height 8px, radius full. Segments proportional to counts. Legend chips below (dot + label + count). Clicking a segment toggles that severity filter on the findings table.

### 4.18 `<Stepper>`
6 horizontal nodes with connector lines. Node states: `pending` (gray ring), `active` (emerald ring + pulse), `done` (filled emerald + check), `failed` (red). Label under each node (12px). Vertical on mobile.

### 4.19 `<PhaseTabs>` (used inside report)
Pills: `All` `Recon` `Auth` `Injection` `Authz` `Logic` `Infra`. Single-select. Count badge per pill.

---

## 5. Data Contracts

Create these in `types/api.ts`. **Do not deviate.**

```ts
// ---------- Health ----------
export type HealthResponse = {
  status: "healthy" | "degraded" | "offline";
  version: string;
  total_checks: number;
  profiles: ProfileId[];
};

// ---------- Profiles ----------
export type ProfileId = "quick" | "full" | "owasp" | "api" | "recon" | "auth";

export type ProfileInfo = {
  id: ProfileId;
  label: string;         // e.g. "Quick Smoke Test"
  description: string;
  check_count: number;
  checks: CheckInfo[];
  est_duration_seconds: number;
};

// ---------- Checks ----------
export type Phase = "recon" | "auth" | "injection" | "authz" | "logic" | "infra";

export type CheckInfo = {
  id: string;              // e.g. "sql-injection-basic"
  name: string;            // e.g. "Boolean-based SQL Injection"
  phase: Phase;
  cwe: string;             // e.g. "CWE-89"
  owasp: string;           // e.g. "A03:2021"
  description: string;
  default_severity: SeverityLevel;
};

// ---------- Scan Launch ----------
export type LaunchScanRequest = {
  url: string;                     // required, http/https
  profile: ProfileId;              // default "quick"
  rate_limit: number;              // 1.0–20.0, default 3.0
  aimd: boolean;                   // default true
  redact: boolean;                 // default true
  exploit_chaining: boolean;       // default true
  cookie_primary?: string;
  cookie_secondary?: string;
  cookie_admin?: string;
  custom_headers?: { key: string; value: string }[];
  scope_exclude?: string;          // newline-separated regex/prefixes
  webhook_url?: string;            // optional valid URL
  abort_after_seconds?: number;    // optional safety cap
};

export type LaunchScanResponse = {
  scan_id: string;                 // uuid
  status: "queued";
  status_url: string;              // e.g. /scan/{id}
  created_at: string;              // ISO8601
};

// ---------- Scan Status ----------
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "aborted" | "paused";

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export type SeveritySummary = Record<SeverityLevel, number>;

export type ScanStatusResponse = {
  scan_id: string;
  url: string;
  profile: ProfileId;
  status: ScanStatus;
  phase: Phase;                    // currently active phase
  phases_completed: Phase[];
  findings_count: number;
  severity_summary: SeveritySummary;
  duration_seconds: number;
  started_at: string;
  finished_at: string | null;
  error_message: string | null;
};

// ---------- Findings ----------
export type Finding = {
  id: string;
  check_id: string;
  title: string;                   // e.g. "Server-Side Template Injection (SSTI)"
  severity: SeverityLevel;
  phase: Phase;
  category: string;                // e.g. "Injection"
  endpoint: string;                // e.g. "/book.html"
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  parameter: string | null;        // e.g. "destination"
  cwe: string;                     // e.g. "CWE-1336"
  owasp: string;                   // e.g. "A03:2021"
  cvss_score: number;              // 0.0–10.0
  cvss_vector: string;             // "CVSS:3.1/AV:N/..."
  confidence: "confirmed" | "likely" | "possible";
  description: string;             // plain-English mechanism
  impact: string;
  evidence: {
    request: string;               // raw HTTP
    response: string;              // raw HTTP
    curl: string;                  // reproduction
    redacted_fields: string[];     // e.g. ["Set-Cookie","Authorization"]
  };
  remediation: {
    summary: string;
    steps: string[];
    code_snippets: { language: string; title: string; code: string }[];
    references: { label: string; url: string }[];
  };
};

// ---------- Report ----------
export type ReportResponse = {
  scan_id: string;
  url: string;
  profile: ProfileId;
  started_at: string;
  finished_at: string;
  duration_seconds: number;
  severity_summary: SeveritySummary;
  cvss_max: number;
  findings: Finding[];
  metadata: {
    rate_limit: number;
    aimd: boolean;
    redact: boolean;
    exploit_chaining: boolean;
    engine_version: string;
    ledger_hash: string;           // for .ledger export verification
  };
};

// ---------- Log ----------
export type LogLine = {
  ts: string;
  level: "debug" | "info" | "warn" | "error" | "success";
  phase: Phase | null;
  message: string;
};

// ---------- Recent Scans ----------
export type ScanListResponse = {
  scans: {
    scan_id: string;
    url: string;
    profile: ProfileId;
    status: ScanStatus;
    severity_summary: SeveritySummary;
    duration_seconds: number;
    created_at: string;
  }[];
};
```

---

## 6. Route Map & Page Registry

| # | Route | Page Name | Purpose |
|---|---|---|---|
| 1 | `/` | Dashboard | Hero launch + metrics + recent scans |
| 2 | `/scans` | Scan History | Full filterable list |
| 3 | `/scans/new` | New Scan Wizard | Advanced configuration |
| 4 | `/scans/[id]` | Live Scan Console | Real-time progress + logs |
| 5 | `/scans/[id]/report` | Interactive Report | Findings + exports |
| 6 | `/catalog` | Check Catalog | Browse 136 checks |
| 7 | `/catalog/[checkId]` | Check Detail | Single check info |
| 8 | `/settings` | Settings | API URL, defaults, theme |
| 9 | `*` | 404 / Error | Not found + connection error |

---

## 7. Page-by-Page Specifications

---

### 7.1 PAGE 1 — Dashboard (`/`)

**Purpose:** Fastest possible path from landing to scan, plus status-at-a-glance.

**Layout (top → bottom):**

#### Section A — Hero
- Container: max-w 720px, centered, mt 48, mb 40.
- **Heading** (display 40/600): `Audit any endpoint in seconds.`
- **Subheading** (16px, `--text-muted`): `Paste a URL. Pick a profile. Get CVSS-scored findings with verified evidence and copy-paste fixes.`
- **Scan bar** (composite, height 52px, radius 12, border 1px `--border-subtle`, bg `--bg-card`):
  - Left icon: `Globe` (18px, `--text-faint`), px-left 16.
  - `<Input>` inline, no border, flex-1, placeholder: `https://your-domain.com`, `type="url"`, `inputMode="url"`, `autoFocus`.
  - Right: `<Button variant="primary" size="lg">Start Assessment</Button>` (48px height, `ArrowRight` icon right).
- **Profile pills** (below scan bar, mt 16, gap 8, wrap):
  - Each pill = `<Button variant={active?primary:secondary} size="sm">` with icon + label:
    - `⚡ Quick` → profile `quick` (default active)
    - `🛡️ OWASP` → `owasp`
    - `🔍 Full` → `full`
    - `🔌 API` → `api`
  - On click → sets `profile` state in the scan form only. No navigation.
- **Text link** (mt 12, 13px, `--text-muted`): `Need authentication or advanced rate limits? Use the advanced wizard →` → `/scans/new`.

#### Section B — Metrics Row (mt 56)
4-col grid, gap 16, responsive (2-col at ≤1024, 1-col at ≤640). Each is a `<MetricCard>`:
1. Label `TOTAL SCANS` · value `{count}` · icon `ScanLine`
2. Label `CRITICAL & HIGH` · value `{sum}` · icon `ShieldAlert` · tone `danger`
3. Label `AVG RUNTIME` · value `{mm:ss}` · icon `Timer`
4. Label `CLEAN ENDPOINTS` · value `{count}` · icon `CheckCircle2` · tone `good`

#### Section C — Recent Scans (mt 56)
- Section header row: `Recent Scans` (H2) + right-aligned `<Button variant="ghost" size="sm" iconRight={ArrowRight}>View all</Button>` → `/scans`.
- `<Table>` columns: `Target` · `Profile` · `Findings` · `Duration` · `Date` · `Status` · `Actions`
  - Target cell: URL truncated at 40 chars (`title` attr full URL), `ExternalLink` icon on hover → opens URL in new tab.
  - Profile cell: `<Badge variant="outline">FULL</Badge>`.
  - Findings cell: severity pills, max 2 (`2C 5H`), tooltip full breakdown on hover.
  - Duration: mono `mm:ss`.
  - Date: relative (`2m ago`) with absolute on hover.
  - Status: `<Badge variant="status-{status}">`.
  - Actions: `View Report` (ghost) if completed, `View Scan` if running/queued, `Re-run` icon button always.
- **Empty state** (no scans): `<EmptyState icon={Radar} title="No scans yet" description="Start your first assessment using the bar above." />`.
- **Loading:** 3 skeleton rows.
- **Error:** inline `<Card>` with `Couldn't load recent scans.` + `Retry` button.

#### API Calls
- `GET /health` → status pill (poll every 30s).
- `GET /scans?limit=10` → recent table (React Query, `staleTime: 10s`).
- `POST /scan` on submit → navigate to `/scans/{scan_id}`.

#### Interactions
- Enter in URL input = submit.
- Submit invalid URL → inline error under input, focus stays, no navigation.
- Submit valid → button enters `loading`, on 201 → `router.push`.
- Profile pills persist selection in `sessionStorage` key `wp.lastProfile`.

---

### 7.2 PAGE 2 — Scan History (`/scans`)

**Purpose:** Full historical list with filters, search, and bulk re-run.

**Layout:**
- Page header: H1 `Scans` + subtitle `All audits launched from this workspace.` + right `<Button primary iconLeft={Plus}>New Scan</Button>` → `/scans/new`.
- **Filter bar** (single row, gap 12, wrap):
  - `<Input>` search (`Search by URL…`, icon `Search`, width 280).
  - `<Select>` `Profile: All / Quick / Full / OWASP / API / Recon / Auth`.
  - `<Select>` `Status: All / Running / Queued / Completed / Failed / Aborted`.
  - `<Select>` `Severity: All / Has Critical / Has High / Clean`.
  - Right side: `Last 7 days` dropdown (7d/30d/90d/All).
- **Active Scans Queue** (only if any status ∈ {running, queued}): a top `<Card>` with title `Active Scans` (with pulse dot). Each row = mini progress bar + phase + elapsed + `Stop` ghost-danger button.
- **Main `<Table>`** (TanStack, virtualized if >100 rows):
  - Columns: `Target` · `Profile` · `Status` · `Critical` · `High` · `Medium` · `Low` · `Duration` · `Created` · `Actions`.
  - Sortable: Target, Status, Duration, Created.
  - Actions cell: `View Report` (if completed) / `View Scan` (if running) + `Re-run` + `Delete` (ghost danger, confirm modal).
- **Pagination:** 50/page, bottom-right, `Previous` / `Next` + page indicator `Page 2 of 7`.
- Empty / loading / error states per §8.

**API:**
- `GET /scans?limit=50&cursor=…` (or client slice from `GET /scans`).
- `DELETE /scan/:id` (if backend supports — otherwise omit button).

---

### 7.3 PAGE 3 — New Scan Wizard (`/scans/new`)

**Purpose:** Advanced configuration with clear groupings and guardrails.

**Layout:**
- Breadcrumb: `Scans / New Scan`.
- H1 `Configure Assessment`.
- **Mode toggle** top-right: segmented `[ Simple | Advanced ]`. Simple hides Tabs 3 & 4 entirely; Advanced shows all.
- **Tabs:** `Target` · `Profiles & Scope` · `Authentication` · `Operational Controls`.
- **Footer action bar** (sticky bottom): left = validation summary `✓ Ready to scan` or `⚠ Fix 2 fields`; right = `<Button secondary>Cancel</Button>` + `<Button primary iconRight={Play}>Start Assessment</Button>`.

#### Tab 1 — Target Definition
Fields (label / placeholder / hint / validation):
- **Target URL** (required) · `https://app.example.com` · hint: `Include protocol. Must be http:// or https://.` · validate RFC 3986, reject non-http(s), reject localhost unless `ALLOW_LOCALHOST` setting on.
- **Scope Excludes** (optional, `<textarea>`) · placeholder lines: `/logout\n/admin/*` · hint: `One path prefix or regex per line. Paths here are never requested.`
- **Allowed Methods** (optional, multi-select checkboxes): `GET / POST / PUT / PATCH / DELETE`. Default = all.

#### Tab 2 — Profiles & Scope
- Grid (3 columns desktop, 1 mobile) of profile cards. Each card:
  - Radio selection (only one active).
  - Icon, Title, Count badge (`7 checks`), Description, Est. duration (`~2 min`).
  - Exact 6 profiles:
    1. **Quick** — `7 checks` — `Fast smoke test: headers, CORS, basic SQLi/XSS.` — `~2 min`
    2. **Full** — `136 checks` — `Comprehensive across all 6 phases.` — `~15 min`
    3. **OWASP** — `21 checks` — `OWASP Top 10 coverage.` — `~8 min`
    4. **API** — `15 checks` — `REST & GraphQL, mass assignment, BOLA.` — `~6 min`
    5. **Recon** — `12 checks` — `Sitemaps, robots.txt, JS endpoints, source maps.` — `~3 min`
    6. **Auth** — `16 checks` — `Password policy, lockout, JWT, session.` — `~5 min`
  - Selected card = emerald border 1px + `--bg-elevated`.
- Below grid: **Checks Preview** collapsible showing the list of check names (chips) from `/profiles`. Max height 200, scroll.

#### Tab 3 — Authentication & Identity (hidden in Simple)
- **Primary Session Cookie** · placeholder `sb-access-token=...; token=...` · hint: `Acts as the "victim" account.`
- **Secondary Session Cookie** · placeholder `sb-access-token=...` · hint: `Second account, for cross-tenant IDOR testing.`
- **Admin Session Cookie** · placeholder `admin=...` · hint: `For vertical privilege escalation checks.`
- Each field has a `Show/Hide` eye toggle (mask default).
- **Custom Headers** — repeatable rows: `[Key] [Value] [+ Add header] [🗑]`. Max 20.

#### Tab 4 — Operational Controls (hidden in Simple)
- **Rate Limit** `<Slider min=1 max=20 step=0.5 default=3.0>` · numeric display `3.0 RPS`.
- **Adaptive Rate Limiting (AIMD)** `<Toggle default=on>` · desc: `Automatically backs off on 429/5xx responses.`
- **PII & Secret Scrubbing** `<Toggle default=on>` · desc: `Redact tokens, cookies, and emails in evidence.`
- **Exploit Chaining** `<Toggle default=on>` · desc: `Allow multi-step chains (e.g. auth bypass → IDOR).`
- **Webhook URL** `<Input type=url>` · placeholder `https://hooks.example.com/webprobe` · optional.
- **Safety Cap** `<Input type=number>` · placeholder `600` · hint `Abort automatically after N seconds.`

#### Interactions
- Next/Back between tabs allowed; Start Assessment always available once Tab 1 valid.
- Start Assessment → builds `LaunchScanRequest`, posts, redirects to `/scans/{id}`. Show toast on success: `Scan queued. Monitoring live console.`
- Cancel → confirm modal if any field dirty: `Discard configuration?` with `Cancel` / `Discard`.

---

### 7.4 PAGE 4 — Live Scan Console (`/scans/[id]`)

**Purpose:** Real-time visibility while scan runs.

**Layout:**
- **Header banner** (Card, sticky top):
  - Row 1: `<Badge status>` + target URL (mono, truncate, copy icon) + `ExternalLink`.
  - Row 2 (right): elapsed timer (`01:42`, mono, live-tick), `<Badge variant="outline">{profile}</Badge>`, `<Button danger iconLeft={Square}>Abort Scan</Button>` (confirm modal).
- **Progress Stepper** (`<Stepper>` horizontal): 6 phases with labels. Active phase pulses.
- **Live metric strip** (3 metric chips, horizontal):
  - `Elapsed` `01:42` · `Requests` `1,248` · `Findings` `7` (animated increment on new).
- **Terminal panel** (`<Terminal>` height 55vh):
  - Top controls: auto-scroll toggle (default ON), search input, `Copy Log` button, `Clear` button (client-side only).
  - Streams `LogLine`s via polling `GET /scan/:id/report?format=log` every 2s (or WebSocket if provided).
  - Each line: `[HH:MM:SS] [LEVEL] [phase] message`, level-colored.
- **Findings-in-progress sidebar** (right, 320px, hidden on mobile): live list of detected findings as clickable rows → drawer (see §7.5 Drawer). Read-only until completion.

**States:**
- **Running:** all above live.
- **Completed:** auto-redirect to `/scans/[id]/report` after 1.5s with toast `Scan complete. Loading report…`.
- **Failed:** Terminal shows error; banner shows `<Badge status-aborted>Failed</Badge>`; new `<Card>` `Scan failed` + `error_message` + `Retry Scan` button (re-posts identical payload).
- **Aborted:** banner updates, terminal frozen, `Retry Scan` offered.

**API (poll every 2s while running):**
- `GET /scan/:id` → `ScanStatusResponse`
- `GET /scan/:id/report?format=log` → `LogLine[]`

**Interactions:**
- Abort → confirm modal `Abort this scan? Partial findings will be saved.` → `POST /scan/:id/abort` (or backend equivalent) → status becomes `aborted`.
- Copy Log → copies joined log text, toast `Log copied to clipboard.`

---

### 7.5 PAGE 5 — Interactive Report (`/scans/[id]/report`)

**Purpose:** Deep triage and remediation.

**Layout:**

#### Header
- Breadcrumb `Scans / {short-id} / Report`.
- H1 = target URL (mono, truncate) + `<Badge status>` + right cluster:
  - `<Button variant="secondary" iconLeft={RefreshCw}>Re-run</Button>`
  - `<DropdownMenu>` `Export` → items: `JSON`, `Markdown`, `SARIF 2.1.0`, `Audit Ledger` (each triggers download + toast `{format} export started.`).

#### Executive Summary Card
3-col grid inside a `<Card>`:
1. **CVSS Max** — big number `9.8`, sublabel `Highest base score`, colored per severity.
2. **Total Findings** — big number `{n}`, sublabel `Across {phases} phases`.
3. **Pass / Fail Gauge** — donut with center `{pass}%` label `Checks passed`.

#### Severity Breakdown
`<SeverityBar>` full-width + legend. Clicking a segment toggles the table filter for that severity (and highlights the chip).

#### Filters & Search (single row)
- Search `<Input>` placeholder `Search title, endpoint, parameter, CWE…` (debounced 200ms).
- `<Select>` Phase: `All` + 6 phases.
- `<Select>` Category (dynamic from data).
- `<Select>` Confidence: `All / Confirmed / Likely / Possible`.
- Right: `Sort` dropdown (`CVSS ↓` default, `CVSS ↑`, `Severity`, `Phase`).

#### Findings Table
Columns (exactly):
1. `Severity` badge
2. `Title` (bold, 14px)
3. `Endpoint` — `POST /book.html` mono + `?param=destination` in `--text-muted`
4. `CWE` (badge outline) · `OWASP` (badge outline) — same cell, gap 4
5. `CVSS` — mono `9.8` with severity-colored dot
6. `Confidence` — small badge
7. `Inspect →` ghost link (opens drawer)

Row click anywhere → opens drawer. Row hover = `--bg-muted`.

#### Finding Detail Drawer (right slide-over — the flagship component)
Structure:
- **Header (sticky):** Severity badge + title (H2) + close X. Below: CVSS pill `9.8 Critical` + mono vector `CVSS:3.1/AV:N/AC:L/...` + copy button.
- **Tabs:** `Overview` · `Evidence` · `Remediation`.

**Tab 1 — Overview:**
- Plain-English `description` (14px/22).
- `impact` block (left-border emerald 2px, muted bg).
- Metadata grid (2-col): `Endpoint` (mono) · `Method` (badge) · `Parameter` · `CWE` (link to cwe.mitre.org) · `OWASP` (link) · `Phase` · `Confidence` · `Check ID` (mono).

**Tab 2 — Evidence:**
- Toggle `Raw HTTP | cURL`.
- `<CodeBlock>`:
  - Request section: `Request` label, mono HTTP raw.
  - Response section: `Response` label, mono HTTP raw.
- Redacted chips row: `[REDACTED:Set-Cookie]` `[REDACTED:Authorization]`.
- `Copy cURL` button top-right.
- Safety: render inside `<pre><code>` only — **never `dangerouslySetInnerHTML`** without DOMPurify.

**Tab 3 — Remediation:**
- `summary` paragraph.
- Numbered `steps` checklist.
- Code snippet tabs (language label on tab): `<CodeBlock showLineNumbers>` per snippet.
- External references list (label + external icon → new tab).

- **Footer (sticky):** left = `Mark as False Positive` (ghost) · right = `Copy Fix`, `Open cURL`, `Close`.

**States:** loading skeleton for the report card + 5 skeleton rows for table. Empty findings → celebratory `<EmptyState icon={ShieldCheck} title="No vulnerabilities detected" description="This target passed all {n} checks in the {profile} profile." action={<Button>Re-run with Full profile</Button>} />`.

**API:**
- `GET /scan/:id` (status)
- `GET /scan/:id/report?format=json` (report)
- Export downloads via `window.location = /scan/:id/report?format={fmt}`.

---

### 7.6 PAGE 6 — Check Catalog (`/catalog`)

**Purpose:** Transparency into what's tested.

**Layout:**
- H1 `Check Catalog` + subtitle `All {136} checks bundled in WebProbe engine v3.0.0.`
- Filter bar: `<Input>` search (name, ID, CWE, OWASP) + `<Select>` Phase + `<Select>` Severity.
- View toggle: `Grid` (default) | `Table`.
- **Grid:** cards (3-col). Each card: check name (H3), ID (mono 12px muted), phase badge, severity badge, CWE + OWASP chips, short description (2-line clamp), footer `View →`.
- **Table:** columns `Name · ID · Phase · Severity · CWE · OWASP · Profiles`.
- Card click → `/catalog/[checkId]`.
- Empty search: `<EmptyState icon={Search} title="No checks match" description="Try a different query or clear filters." />`.

**API:** `GET /profiles` → derive union of checks.

---

### 7.7 PAGE 7 — Check Detail (`/catalog/[checkId]`)

**Purpose:** Explain a single check.

**Layout:**
- Back link `← Catalog`.
- H1 = check.name + severity badge + phase badge.
- 2-col info grid: ID, CWE, OWASP, phase, default severity, included in profiles (chips).
- Description paragraph.
- Card: `What this check does` (description), `What triggers a finding` (bullets), `Remediation reference` (links).
- Right rail: `Included in` profile chips + `Run this check` CTA (`Start Quick Scan` prefilled to that check if backend supports, else `Start Full Scan`).

**Empty/error:** If not found → 404 page §7.9.

---

### 7.8 PAGE 8 — Settings (`/settings`)

**Purpose:** Configure client behavior + defaults.

**Sections (each a `<Card>`):**
1. **Backend Connection**
   - `API Base URL` `<Input>` default `http://localhost:8080` (from `NEXT_PUBLIC_API_URL`).
   - `Test Connection` button → toast `Connected · v3.0.0` or `Connection failed`.
   - Status pill mirrors nav.
2. **Scan Defaults**
   - `Default Profile` `<Select>` (quick/full/owasp/api).
   - `Default Rate Limit` `<Slider 1–20>`.
   - `AIMD enabled by default` `<Toggle>`.
   - `Redact by default` `<Toggle>`.
3. **Notifications**
   - `Webhook URL` `<Input>`.
   - `Notify on complete` `<Toggle>`.
   - `Notify on critical finding` `<Toggle>`.
4. **Appearance**
   - `Theme` segmented `[ System | Dark | Light ]`, default `Dark`.
   - `Reduce motion` `<Toggle>`.
5. **Data**
   - `Clear local scan history` (danger ghost) → confirm modal `This clears your local cache only.` → clears `localStorage` keys.
   - `Export my settings` (JSON download).

**Persistence:** every field saves to `localStorage` under `wp.settings` immediately (debounced 300ms). Show `Saved` micro-text fading after 1s.

---

### 7.9 PAGE 9 — 404 / Error

**404 (`/not-found.tsx`):**
- Center: `404` (display), `Page not found.` (H2), `The page you're looking for doesn't exist or was moved.` (muted), `<Button primary>Back to Dashboard</Button>`.

**Backend offline (global fallback):**
- Full-page `<Card>`: `Backend unreachable.` (H2), `WebProbe can't reach the API at {url}. Start the server and retry.` + `Retry` + `Open Settings` buttons.

---

## 8. State Matrix

Every data-driven surface must handle all 4 states. Reuse this table verbatim.

| Surface | Loading | Empty | Error | Success |
|---|---|---|---|---|
| Backend status | pulsing gray dot | — | red dot `Offline` | green dot `Connected · v3.0.0` |
| Metric cards | skeleton blocks | `0` values | `—` + tooltip `Unavailable` | animated number |
| Recent scans table | 3 skeleton rows | `<EmptyState>` (§7.1) | `Couldn't load recent scans.` + Retry | rows |
| Scan history | 6 skeleton rows | `No scans match your filters.` | `Couldn't load scans.` + Retry | rows |
| Live console | `Connecting to scan…` centered + spinner | — | `Lost connection. Retrying…` banner + auto-retry | streams |
| Report | skeleton header + 5 skeleton rows | clean `<EmptyState>` (§7.5) | `Couldn't load report.` + Retry | rendered |
| Findings table | 5 skeleton rows | `No findings match your filters.` + `Clear filters` | `Couldn't load findings.` | rows |
| Drawer | skeleton blocks | — | `Couldn't load finding details.` | tabs |
| Catalog | skeleton cards ×6 | search-empty `<EmptyState>` | `Couldn't load catalog.` | grid/table |
| Settings | skeleton fields | — | `Save failed. Retrying…` toast | `Saved` micro |

---

## 9. Exact Copy Library

**Only these strings may be used. No invented marketing copy.**

| Context | Copy |
|---|---|
| Hero H1 | `Audit any endpoint in seconds.` |
| Hero sub | `Paste a URL. Pick a profile. Get CVSS-scored findings with verified evidence and copy-paste fixes.` |
| URL placeholder | `https://your-domain.com` |
| Primary CTA | `Start Assessment` |
| Advanced link | `Need authentication or advanced rate limits? Use the advanced wizard →` |
| Backend connected | `Connected · v3.0.0` |
| Backend offline | `Offline` |
| Scan queued toast | `Scan queued. Monitoring live console.` |
| Scan complete toast | `Scan complete. Loading report…` |
| Abort button | `Abort Scan` |
| Abort modal title | `Abort this scan?` |
| Abort modal body | `Partial findings will be saved. You can re-run later.` |
| Abort confirm | `Abort Scan` |
| Abort cancel | `Keep Running` |
| Export labels | `JSON`, `Markdown`, `SARIF 2.1.0`, `Audit Ledger` |
| Copy log toast | `Log copied to clipboard.` |
| Copy cURL toast | `cURL command copied.` |
| Clean scan empty | `No vulnerabilities detected` / `This target passed all {n} checks in the {profile} profile.` |
| No scans empty | `No scans yet` / `Start your first assessment using the bar above.` |
| Catalog empty | `No checks match` / `Try a different query or clear filters.` |
| Settings saved | `Saved` |
| Discard config modal | `Discard configuration?` / `Your changes won't be saved.` |
| 404 | `Page not found.` / `The page you're looking for doesn't exist or was moved.` |
| Backend error page | `Backend unreachable.` / `WebProbe can't reach the API at {url}. Start the server and retry.` |

---

## 10. Interaction Rules

- **Global:** `⌘K` opens palette · `Esc` closes topmost overlay · `/` focuses search on list pages.
- **Scan form:** `Enter` submits when URL valid.
- **Tables:** row click = primary action (open drawer or navigate). Action buttons `e.stopPropagation()`.
- **Drawer:** focus trap, restore focus to trigger row on close.
- **Redirects:** after scan completion on console → 1.5s delay then push report.
- **Errors:** never silent. Every failed fetch → toast + surface-level retry.
- **Confirmations:** required for Abort Scan, Delete scan, Discard config, Clear local data.
- **Polling:** React Query — status 2s while running, 30s when idle, `refetchOnWindowFocus=false` for status, `true` for health.
- **localStorage keys:** `wp.settings`, `wp.lastProfile`, `wp.recentScanIds` (array, cap 20).

---

## 11. Defaults, Fallbacks & Validation

| Field | Default | Validation | On Invalid |
|---|---|---|---|
| `url` | — (required) | non-empty, RFC 3986, scheme ∈ http/https | `Enter a valid http(s) URL.` |
| `profile` | `quick` | one of 6 IDs | fallback `quick` |
| `rate_limit` | `3.0` | 1.0–20.0 | clamp |
| `aimd` | `true` | boolean | — |
| `redact` | `true` | boolean | — |
| `exploit_chaining` | `true` | boolean | — |
| `cookie_*` | `""` | non-blocking | — |
| `webhook_url` | `""` | valid URL if provided | `Enter a valid webhook URL.` |
| `abort_after_seconds` | `600` | ≥30 | clamp |
| Theme | `dark` | system/dark/light | `dark` |

**Unspecified anything:** if backend omits a field, render placeholder `—` (mono muted) — never crash, never invent a value.

---

## 12. Responsive & Accessibility

**Breakpoints:** `sm 640 · md 768 · lg 1024 · xl 1280 · 2xl 1440`.
- Dashboard: 4 metrics → 2 → 1. Hero scan bar → stacked (CTA full-width below input).
- Report: table → cards at `<768px`. Drawer → full-screen at `<768px`. SeverityBar wraps legend.
- Console: sidebar hidden `<1024`.
- TopNav: collapses at `<768` to hamburger.

**A11y (WCAG AA minimum):**
- All interactive elements focus-visible ring: 2px `--accent-emerald` offset 2.
- Color contrast ≥ 4.5:1 for text; severity badges additionally include a `title` + `aria-label` with severity name (never rely on color alone).
- All icon-only buttons have `aria-label`.
- Tables: `<caption class="sr-only">` + proper `<th scope>`.
- Drawer & modal: `role="dialog"`, `aria-modal="true"`, labelled by title, focus trap, Esc.
- Live regions: findings count and status updates use `aria-live="polite"`.
- Honor `prefers-reduced-motion`.

---

## 13. Implementation Order Checklist

Do these in order. Do not skip ahead.

- [ ] 1. Init Next.js 14+ (App Router, TS) + Tailwind + shadcn/ui. Add tokens from §2 to `tailwind.config`.
- [ ] 2. Build `<AppShell>`, `<TopNav>`, `<Footer>`, `<Toaster>`, `<CommandPalette>` (§3).
- [ ] 3. Build component library (§4) — Button, Input, Select, Toggle, Slider, Badge, Card, MetricCard, Table, Drawer, Modal, Tabs, CodeBlock, EmptyState, Skeleton, Terminal, SeverityBar, Stepper, PhaseTabs.
- [ ] 4. Write `types/api.ts` verbatim from §5.
- [ ] 5. Write `lib/api.ts` — typed fetch wrappers with base URL from `wp.settings` → `NEXT_PUBLIC_API_URL`.
- [ ] 6. Build Page 1 Dashboard (§7.1).
- [ ] 7. Build Page 3 New Scan Wizard (§7.3) — all 4 tabs.
- [ ] 8. Build Page 4 Live Console (§7.4) with polling + stepper + terminal.
- [ ] 9. Build Page 5 Report (§7.5) — SeverityBar + table + **Finding Drawer** (highest effort).
- [ ] 10. Build Page 2 Scan History (§7.2).
- [ ] 11. Build Pages 6 & 7 Catalog + Check Detail (§7.6–7.7).
- [ ] 12. Build Page 8 Settings (§7.8) + localStorage persistence.
- [ ] 13. Build Page 9 404 + backend-offline fallback (§7.9).
- [ ] 14. Wire all state matrix entries (§8) — verify every surface.
- [ ] 15. Audit against §9 (copy), §10 (interactions), §11 (defaults), §12 (a11y/responsive).
- [ ] 16. Final pass: run `axe` and Lighthouse; fix regressions before shipping.

---

**Document ended.** Any question that arises during build should be resolved by re-reading the nearest numbered section. If truly unanswerable, default to the **simplest Vercel/Linear-style pattern** and record it under "Assumptions" in the PR — do not free-form design.

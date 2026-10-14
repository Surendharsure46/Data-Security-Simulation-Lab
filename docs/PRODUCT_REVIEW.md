# Threatready product review and improvement plan

The simulation engine, scoring and labs work and are tested; what stops Threatready being customer-ready is how it looks and guides people. A new user sees 16 technical menu items, a crowded top bar and dense pages with no clear first step. About 5 working days of must-have changes, mostly to the screens, make it ready to hand to a customer; about 7 with the polish items.

## What the screenshots show

The four screenshots point to the same root cause: the interface was built around the system's features, not around the first-time user's journey. The biggest problems are in the menu and the top bar, which every page shares.

| # | Problem | Where | Effect on a new user | Severity |
| --- | --- | --- | --- | --- |
| 1 | 16 menu items in 4 groups, with module codes (M01…M09); the list needs scrolling on a laptop | Left menu (circled) | Does not know where to start or what most items mean | High |
| 2 | Top bar crowded with technical items: workspace selector, ACTIVE, Sim clock in UTC, SIMULATED, user, Sign out | Top bar (circled) | Spends attention on status words that rarely matter | High |
| 3 | No clear first step. The dashboard opens with a 10-word process chain, three cards, a 10-row skill list and a levels table | Overview Dashboard | Cannot tell what to click first | High |
| 4 | Pages lead with jargon: "Detector results are evidence for your decision", SHA-256 hex strings, AES-256-GCM + scrypt | Data Discovery, Encryption Lab | Reading is hard; the purpose of the page is unclear | Medium |
| 5 | Dark theme by default with light grey text on dark blue, many coloured badges | All pages | Low contrast for long reading; badges compete for attention | Medium |
| 6 | Simulation steps are spread across 6 separate menu pages; the learner must remember the order | Scenario workspace | Gets lost between steps; no "Next" button | High |
| 7 | Labs show all exercises at once (e.g. 5 long cards on Encryption Lab) | Labs | Long scrolling pages; no sense of progress | Medium |
| 8 | Wide tables with many columns and long file paths | Discovery, Events, Classification | Text wraps awkwardly; key columns cut off | Low |

No functional defects were visible in the screenshots: the problems are layout, wording and guidance.

## Recommended changes

Twelve changes, ordered by priority. Changes A–F fix the problems a customer notices in the first five minutes; G–L polish and complete the product. None of them change the simulation logic or scoring, which stay as tested.

| ID | Change | Fixes | Effort | Priority |
| --- | --- | --- | --- | --- |
| A | **Welcome screen** after first sign-in: what Threatready is in two sentences, a 3-step picture of the journey, one button "Start your first simulation" | 3 | 0.5 day | Must |
| B | **Simpler menu**: 5 plain items (Home, Simulation, Practice Labs, Learning, Results); advanced tools (Event Explorer, Engineering, Admin) moved under "More"; module codes removed | 1 | 0.5 day | Must |
| C | **Guided simulation flow**: one Simulation page with a step bar (Find → Label → Set rules → Run the day → Investigate → Fix & verify → Report), one focused screen per step and a Next button | 6 | 1.5 days | Must |
| D | **Calmer top bar**: show only the simulation name, a progress indicator and the user menu; move sim clock, status and SIMULATED into a small "i" info pop-over | 2 | 0.25 day | Must |
| E | **Light theme by default** with a dark-mode toggle; larger body text (16 px), more spacing, fewer coloured badges | 5 | 0.5 day | Must |
| F | **Plain-language page intros**: every page opens with "What you do here" in one sentence and "Why it matters" behind a "Learn more" link; technical detail folded away | 4 | 0.5 day | Must |
| G | **Simple dashboard**: one "Continue where you left off" card, a progress ring and next lesson; skill table and levels moved to Learning | 3 | 0.5 day | Should |
| H | **Labs as steppers**: one exercise at a time with progress ("Exercise 2 of 5"), long hashes shortened with a copy button | 7 | 0.5 day | Should |
| I | **In-app help**: the User Manual linked from a "?" button; short tooltips on unfamiliar words (DLP, Sim clock, Disposition) | 4 | 0.25 day | Should |
| J | **Tidier tables**: fewer default columns, "show more" for details, file paths shortened | 8 | 0.25 day | Should |
| K | **Accessibility and responsive check**: keyboard path, contrast ratios, tablet layout | 5 | 0.5 day | Should |
| L | **Customer packaging**: installer or Docker image tested, admin guide, demo account, release notes, React Router 7 upgrade | — | 1 day | Must before delivery |

Effort is an estimate for one developer working with me, including testing.

## Where each change pays off

| | Half a day or less | A day or more |
| --- | --- | --- |
| **High impact on a new user** | **Quick wins, do first:** A Welcome screen, B Simpler menu, D Calmer top bar, E Light theme and bigger text, F Plain-language page intros | **Big steps, plan them:** C Guided step-by-step flow, L Customer packaging |
| **Lower impact** | **Polish, when time allows:** G Simple dashboard, H Labs as steppers, I In-app help, J Tidier tables, K Accessibility check | **Costly, little gain:** nothing recommended here |

Start with the five quick wins: together they take about 2.25 days and remove most of what made the screens feel crowded. The guided flow (C) is the single biggest improvement and gets its own phase.

## Delivery plan

Three phases take Threatready from today's working build to a customer release in about 7 working days. Each phase ends with a check you can see for yourself.

1. **Phase 1 — First impression (about 2.25 days):** changes A, B, D, E, F. Check: a colleague who has never seen the product signs up and starts a simulation without help.
2. **Phase 2 — Guided journey (about 2.75 days):** changes C, G, H, I, J. Check: the same colleague finishes the whole simulation in under 90 minutes using only the in-app guidance and the User Manual.
3. **Phase 3 — Customer release (about 1.5 days):** changes K and L, full regression tests, updated User Manual screenshots, release notes. Check: a clean install on a second Windows machine works from the instructions alone.

After the release, the next product milestone is the enterprise capstone scenario and a second scenario, so returning learners have new material.

## Customer-readiness checklist

Tick these before handing Threatready to a customer. The first four are already true today.

- [x] Reference simulation works end to end and passes automated browser tests
- [x] Scores are calculated on the server and explained point by point
- [x] No known security vulnerabilities in backend dependencies
- [x] User Manual written
- [ ] A first-time user can start a simulation without help (Phase 1 check)
- [ ] A first-time user can finish the simulation using only in-app guidance (Phase 2 check)
- [ ] Light theme, readable text and keyboard navigation verified
- [ ] Clean install tested on a second machine from the written instructions
- [ ] Administrator guide: install, create users, back up, reset
- [ ] Demo account and sample results for sales demonstrations
- [ ] User Manual updated with screenshots of the new screens
- [ ] Release notes and version number agreed
- [ ] Remaining moderate React Router advisory closed (upgrade to v7)

## Open questions for you

- Who is the first customer: individual learners, a company training its security team, or a college? This decides whether the Learning section or the simulation comes first on the home screen.
- Will customers install Threatready themselves, or will you host it for them? Hosting needs HTTPS, backups and a proper login (for example company single sign-on).
- Should the product keep both guided and assessment modes on the first screen, or show assessment only after a guided run?
- Do you want your own branding (logo, colours, product name on reports)?

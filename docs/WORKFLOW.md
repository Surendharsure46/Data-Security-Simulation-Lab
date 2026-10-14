# Learner journey (Levels 0–5)

Threatready is a guided, step-by-step learning journey. A beginner meets data security on a public welcome page, learns how the platform works, chooses a role and then climbs six levels. Each level has short fundamentals, a knowledge check and hands-on labs. Finishing a level shows a congratulations popup, and the next level unlocks automatically.

```
Welcome to Data Security (public)  ──[Let's Get Started, top right]──►  How Threatready works + choose your role (public)
  → create account / sign in (the chosen role is applied)  →  My Journey (level map, "Continue" next step, guided tour)
  → Level n:  read the fundamentals (one lesson per screen)  →  knowledge check (5 questions, 4 to pass)
              → hands-on labs in order, each a guided lab session:
                   Understand the business problem → Inspect → Act → Observe → Validate → Explain and submit
                   → server-side competency assessment → required criteria met?
                        no  → skill gaps + remedial lesson → retry (practice, or a new variant for simulation labs)
                        yes → skills recorded → next lab
  → level complete → 🎉 congratulations popup (new title, responsibilities, harder challenges) → Level n+1 unlocked
  → … → Level 5 complete → journey complete
```

## Screens

| Screen | Route | Purpose |
|---|---|---|
| Welcome | `/` (signed out) | Detailed introduction to data security (CIA triad, data lifecycle, what goes wrong, what professionals do), why to learn here, the six levels. **Let’s Get Started** sits in the fixed top-right corner. |
| Get started | `/get-started` | How the platform works, what you do in every level, the Level 0–5 path, role cards, then account creation or sign-in. The role is applied right after the account exists. A signed-in user without a role sees the same page with a **Start my journey** button. |
| My Journey | `/` (signed in) | Role title, overall progress, a **Continue** card that always points at the next step, the six-level path (completed, current, locked) with progress bars, recorded skills, recent results. Shows a guided tour on first visit (restart it with **? Guided tour** in the top bar). |
| Level | `/levels/:n` | "Before you start", responsibilities and challenge, plus the numbered step list (lessons, knowledge check, labs) with status and a **Continue** button. |
| Lesson reader | `/levels/:n/learn/:key` | One lesson per screen with progress dots, Previous / **Got it — next** and a link to where the concept is practised. Level 0 starts with the Kestrel Ridge organisation briefing. |
| Knowledge check | `/levels/:n/check` | Five server-graded questions. Option order is shuffled in a stable way and answers never reach the browser. Passing unlocks the level's labs. |
| Lab session | `/missions/:id` | **Hands-on labs and the demo:** the lab runs embedded on the left, filtered to the exercises being practised. A sticky instructor panel on the right walks through each step with numbered instructions, keeps the checklist live as the server verifies results, and holds the explanation form. **Simulation labs:** the six-phase view with links into the toolkit (Discovery, Classification, DLP Policy Studio, Investigation, Workspace). The result shows required criteria, recorded skills or skill gaps, remedial lessons and retry options. |
| Congratulations popup | global | Appears whenever `pending_promotion` is set: completed level, new title, new responsibilities, harder challenges, **Start Level n+1**. |

Navigation is short and colour-coded: **Learn** in neon purple (My Journey · Current level · Continue next step), **Progress** in cyan (Skills & Progress · Learning Library · Assessment & Reports) and **Tools** in pink.

### Tools unlock level by level

The standalone tool pages unlock with the level that first uses them, so a beginner never faces advanced tools before learning what they are for. Locked tools show 🔒 and their level in the sidebar, and opening one directly explains when it unlocks. Inside a lab session every tool that lab needs is already available. Instructors and administrators see everything. This is a guidance lock in the interface, not a security boundary.

| Unlocks at | Tools |
|---|---|
| Level 0 | Encryption Lab |
| Level 1 | Simulation Workspace, Data Discovery, Classification Studio, DLP Policy Studio, Security Event Explorer, Incident Investigation, Database Security Lab |
| Level 3 | Data Security Engineering |
| Level 4 | Privacy & Governance, Cloud Data Security, AI Data Security, Real-Tool Practice |
| Staff only | Administrator Settings |

Source of truth: `frontend/src/components/toolAccess.tsx` (`TOOLS`, `LevelGate`).

### Colour palette

White surfaces and text, purple as the primary colour (`#7c3aed` light / `#b56cff` dark), and neon accents: cyan `#2ef2ff`, pink `#ff5ce1`, green `#39ffa8`. The tokens live at the top of `frontend/src/styles.css`.

## Levels

| Level | Title (rank) | Fundamentals | Labs |
|---|---|---|---|
| 0 Foundation | Trainee | Kestrel Ridge briefing + 5 lessons | MSN-001 *Your first data protection move* (interactive demo: real detectors and policy engine) · MSN-002 *Spot the tampered payroll file* (hashing) |
| 1 Practitioner | Junior | 8 lessons | MSN-101 *Find and protect the customer export* (simulation, guided) · MSN-102 *Prove file encryption* · MSN-103 *Close the support database gaps* |
| 2 Analyst | — | 7 lessons | MSN-201 *Handle an exfiltration incident without help* (simulation, independent) · MSN-202 *Find the bulk reader in the audit log* |
| 3 Engineer | Senior | 8 lessons | MSN-301 *Masking and recoverability* · MSN-302 *Key rotation and config hardening* · MSN-303 *Engineer the fix without breaking the business* (simulation, independent) |
| 4 Architect | Lead | 9 lessons | MSN-401 *Privacy review* · MSN-402 *Reduce cloud exposure* · MSN-403 *Secure the AI assistant rollout* · MSN-404 *What TLS still reveals* |
| 5 Mastery | Principal | Mastery note + 1 lesson | MSN-501 *Lead the incident end to end* (simulation, independent, pass mark 85, ≥ 80 % per category) |

The title is the rank plus the chosen role, e.g. *Junior DLP Engineer*. The roles are Data Security Generalist, Data Security SOC Analyst, DLP Engineer and Data Protection Engineer. A role sets the title, the skills highlighted for you and the Learning Library pathway. Every role follows the same six levels.

## Implementation map

| Concern | Where |
|---|---|
| Content: welcome text, platform overview, roles, ranks, levels, knowledge checks, missions, per-exercise instructions, skills | `backend/app/content/career.py` (validated by `validate_career_content()` at start-up, in `app.cli validate-content` and in tests) |
| Logic: role choice, fundamentals read-tracking, knowledge checks, step sequencing, mission start/retry/submit, assessment branches, automatic level unlock (cascades when earlier work already completes a level), skills | `backend/app/services/career.py` |
| API | `backend/app/routers/career.py`: `GET /public` (no auth), `GET /profile`, `PUT /role`, `GET /journey`, `GET /levels/{n}`, `POST /levels/{n}/read/{key}`, `POST /levels/{n}/check`, `POST /demo/{scan,classify,transfer}`, `GET /missions/{id}`, `POST /missions/{id}/start`, `GET /attempts/{id}`, `POST /attempts/{id}/{understand,submit,retry}`, `GET /promotion`, `POST /promotion/acknowledge` |
| Data | `LearnerProfile` (role, level, read lessons, demo progress, pending celebration), `MissionAttempt`, `SkillRecord`, knowledge checks as `LabExerciseResult(lab="knowledge", exercise="LEVEL-Ln")`; migrations `0002`, `0003` |
| Frontend | `pages/public/{Welcome,GetStarted}.tsx`, `pages/journey/{Journey,Level,nav}.tsx`, `pages/Mission.tsx` (lab session + simulation view), `components/{LevelUpModal,Tour,DemoLab}.tsx`, lab pages accept `embedded` / `focus` props |

## Rules and honesty notes

- **Server-side grading only.** Lesson reading is tracked for guidance, but only knowledge checks, lab results and scenario assessments are graded, all on the server.
- **Practice cannot pass an independent lab.** A practice retry of an independent simulation lab runs in guided mode. It is assessed, but its best result is `PRACTICE_PASSED`.
- **Lab sessions stay in the workflow.** Sessions linked to a lab refuse the plain `/sessions/{id}/submit` and `/reset`; submission needs the explanation and cited evidence.
- **Earlier lab work counts.** Labs record each exercise once, so an exercise verified earlier counts toward a later lab.
- **Migration 0003 resets journey state.** Existing learners return to *choose a role* at Level 0. Their passed labs are kept and count again as they reach each level.
- **Practice sandbox stays.** The Simulation Workspace launcher still offers free practice sessions; they do not count toward levels.

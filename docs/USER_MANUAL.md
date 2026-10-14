# Threatready User Manual

Threatready lets you practise real data-security work on a fictional company, Kestrel Ridge Financial. This manual shows you where everything is and walks you through your first simulation, one step at a time. Nothing you do here touches a real system or real people.

## Getting started

You need a web browser and the address your administrator gave you (on a local install it is **http://127.0.0.1:5180**).

1. Open the address in Chrome or Edge.
2. Click **Create learner account** the first time. Next time, use **Sign in**.
3. Enter your **email address**, a display name and a password.
4. Enter a **display name**. This is the name shown on screen.
5. Choose a **password** of at least 10 characters, with an uppercase letter, a lowercase letter and a digit.
6. Click **Create account**. You land on the **Overview Dashboard**.

If the page says *Cannot reach the Threatready server*, the API is not running. See **Troubleshooting** at the end.

## The screen at a glance

Every page has the same areas:

```
+--------------------+--------------------------------------------------------------+
| 1  MENU            | 2  TOP BAR                                                   |
|                    |    Active workspace (which simulation you are working on)    |
| Learn              |    Status, sim clock (story time), SIMULATED badge, Sign out |
|  home and lessons  +--------------------------------------------------------------+
|                    | 3  WORK AREA                                                 |
| Scenario workspace |    Page title, one-line explanation, main buttons            |
|  simulation steps  |                                                              |
|                    |    +-------------------------+   +------------------------+  |
| Labs               |    | List of items           |   | 4  DETAILS PANEL       |  |
|  stand-alone       |    | (files, alerts, events, |-->| everything about the   |  |
|  practice          |    |  policies)              |   | row you clicked and    |  |
|                    |    | click a row to open it  |   | the actions you can    |  |
| Results            |    |                         |   | take                   |  |
|  score, reports    |    +-------------------------+   +------------------------+  |
|                    |                                                              |
| START HERE:        |                                                              |
| Simulation         |                                                              |
| Workspace          |                                                              |
+--------------------+--------------------------------------------------------------+
```

Whatever page you are on, you choose *where to go* in the menu (1), check *which simulation you are in* on the top bar (2), and do the work in the middle (3). On most pages, clicking a row in a list opens its details on the right (4).

The top bar shows the same items everywhere:

| Item on the top bar | What it means | Do I need to touch it? |
| --- | --- | --- |
| **Active workspace** box | The simulation you are working on. Every page under *Scenario workspace* shows this simulation. | Only to switch between simulations |
| **ACTIVE** (or PAUSED, SUBMITTED) | Whether you can still make changes. | No |
| **Sim clock** | The date and time inside the story. It moves forward as you act. It is not your real clock. | No |
| **SIMULATED** | A reminder that everything here is made-up practice data. | No |
| Your name and **Sign out** | Who is signed in. | When you finish |

## The menu explained

The left menu has four groups. As a new user you only need two items at first: **Overview Dashboard** and **Simulation Workspace**. Everything under *Scenario workspace* works on the simulation you have open.

| Menu item | What it is for | When you use it |
| --- | --- | --- |
| **Learn** | | |
| Overview Dashboard | Your home page: progress, next recommended task, recent work | Every time you sign in |
| Learning Paths | Lessons, levels L0–L5, knowledge checks and specialist pathways | To pick what to learn next |
| **Scenario workspace** | | |
| Simulation Workspace | Start, pause, reset and run a simulation; shows your task checklist | Start here for every simulation |
| Data Discovery | Scan the company's files and databases for sensitive data | Step 1 of a simulation |
| Classification Studio | Label data (Public to Restricted), set owners, review who has access | Step 2 |
| DLP Policy Studio | Write rules that allow, warn about or block data transfers, and test them | Step 3 |
| Security Event Explorer | Search every event the simulation recorded | While investigating |
| Incident Investigation | Triage alerts, open a case, record evidence, contain and write the report | Steps 5–7 |
| Data Security Engineering | Measure how well your rules work against test cases | Optional, advanced |
| **Labs** | | |
| Encryption Lab, Database Security Lab, Privacy & Governance, Cloud Data Security / DSPM, AI Data Security | Stand-alone practice exercises (see **Practice labs**) | Any time; they do not need a simulation |
| Real-Tool Practice | Which real tools are available and step-by-step guides for outside tools | When you want to go beyond the platform |
| **Results** | | |
| Assessment & Reports | Submit your simulation, see your score, download reports | At the end of a simulation |
| Administrator / Lab Settings | Users, roles and audit log (administrators and instructors only) | Not needed by learners |

The small codes next to some items (M01, M02 …) are the module numbers used in **Learning Paths**.

## Your first simulation, step by step

The simulation *Unauthorized Customer-Data Export* takes about 75 minutes. You play the company's Data Protection Analyst: someone will try to move a customer file out of the company during a normal business day, and your job is to stop, investigate and fix it. The **Progress** checklist on the right of the Simulation Workspace ticks off each task as you complete it.

1. **Start the simulation.** Click **Simulation Workspace**, then **Start guided practice**. Guided mode gives hints; *independent assessment* gives none and picks a random version of the story. Read the **Briefing** card.
2. **Find the data.** Click **Data Discovery**, then **Run discovery scan**. Click the row `customer_master_export_2026Q1.csv`. On the right you see what it contains (card numbers, emails), that it has **no owner** and **no label**, and who can open it.
3. **Label the data.** Click **Classification Studio**, click the export row, choose a **Label** (think: bulk customer data with card numbers), choose a **Data owner**, write a short **Justification**, and click **Save classification**. Label the other unlabeled files too.
4. **Review access.** In Classification Studio, open the **Ownership & access review** tab. For each permission on the export, type a note and click **KEEP** or **REVOKE**. Revoking changes who can read the file.
5. **Write a rule.** Click **DLP Policy Studio**, then **New policy**. Give it a key such as `POL-DLP-CUSTOMER`, set **Outcome** to **BLOCK**, keep the condition *destination.sanctioned eq false*, click **+ Condition** to add *content.label label_at_least confidential*, and click **Save policy**.
6. **Test the rule.** Open the **Test workspace** tab and click **Test against saved policies**. Try one transfer that should be blocked and one that should be allowed (for example the marketing brochure). The trace shows exactly which condition matched.
7. **Run the business day.** Back in **Simulation Workspace**, click **Run business day**. Ten activities happen through the controls you set up. A message tells you how many events, alerts and blocked actions there were.
8. **Triage the alerts.** Click **Incident Investigation**. Click each alert, read *Why the rule fired* and the related events, choose a **Disposition** (real problem, legitimate activity, or not sure) and give a reason.
9. **Investigate.** On the most serious alert click **Open case from this alert**. In the case: click **Link as evidence** on the key events, add notes (an *Observation* must cite evidence; add an *Inference* and an *Unknown* too), then on **Scope & severity** record what was affected, use the **Risk model calculator**, and pick root causes.
10. **Contain and fix.** On **Containment & remediation**, preserve evidence *before* any device action, then disable the account and escalate to the Privacy Office. Fix the root cause: revoke the excessive permission and make sure your DLP rule blocks.
11. **Prove the fix.** In **Simulation Workspace** click **Run control-validation replay**. The day runs again with a test copy of the person's account; the risky transfer should now be stopped while normal work still succeeds.
12. **Write the report.** In the case, open the **Report** tab and fill in summary, root cause, residual risk and lessons learned. Click **Save report sections**.
13. **Submit.** Click **Assessment & Reports**, then **Submit for assessment**. You get a score out of 100 with an explanation for every point lost, and you can view or download the incident report.

To try again, click **Reset** in the Simulation Workspace. Your submitted result is kept and you can get a different version of the story.

## Practice labs

Labs are short, self-contained exercises that do not need a simulation. Each lab page lists numbered exercises; a green **Exercise passed** badge appears when the server has checked your work. Every lab has a **Reset** button, so you can repeat it.

| Lab | What you practise | Real or simulated | Exercises |
| --- | --- | --- | --- |
| Encryption Lab | Spotting a tampered file with hashes, encrypting a file and proving a wrong password or tampering is rejected, rotating encryption keys, what TLS hides, fixing a weak encryption setup | Real (exercises 1–3), simulated (4–5) | 5 |
| Database Security Lab | Least-privilege roles, SQL injection vs safe queries, masking card numbers, spotting suspicious queries in an audit log, backup and restore | Real (a private practice database) | 5 |
| Privacy & Governance | Deciding which fields a marketing list really needs, retention rules, deleting old records without touching those under legal hold, a findings report | Simulated | 3 |
| Cloud Data Security / DSPM | Finding the most exposed storage bucket, reducing exposure without breaking the public website | Simulated | 2 |
| AI Data Security | Stopping sensitive prompts to an unapproved AI tool, stopping an AI assistant from showing documents a user should not see, safe AI log settings | Simulated | 3 |

*Real* means the operation actually runs on your computer, on throw-away practice files. *Simulated* means the platform models the situation; no real cloud account or AI service is contacted.

## Lessons, levels and your results

A lesson counts as complete only when you have done the practical work it asks for: a simulation task, a lab exercise or a short quiz. Reading alone does not complete a lesson.

- **Levels** run from L0 Foundation to L5 Independent Mastery. A level unlocks when you finish enough lessons in the level below.
- **Pathways** let you focus: Foundations, DLP Engineer, SOC Analyst or Data Protection Engineer. Choose one in **Learning Paths**; its lessons unlock even if they belong to a higher level.
- **Quizzes** have four questions and need 75% to pass. You see which answers were wrong, not the right answer, so you can retry fairly.

When you submit a simulation you get a **score out of 100**, made of five parts:

| Part | Weight | What it checks |
| --- | --- | --- |
| Technical correctness | 25% | Correct labels and removing excessive access |
| Detection and analysis | 25% | Alert decisions, the case conclusion, severity |
| Evidence quality | 20% | Linked evidence and clear notes |
| Remediation and validation | 20% | The replay shows the problem fixed without blocking normal work |
| Documentation and escalation | 10% | Report sections and escalating to Privacy or Legal |

You pass with **70 or more**, unless you hit a *critical failure*: wiping the person's laptop before preserving evidence, or never proving your fix with a replay. Every lost point comes with a one-line explanation and a suggested lesson.

**Reports** (in **Assessment & Reports**) are built from what you actually did: data inventory, classification register, policy tests, incident timeline, the full incident report, remediation results and your assessment. Download them as Markdown, HTML, JSON or CSV.

Scores are a platform result for this exercise. They are not a professional certification.

## Words and badges you will see

| Word or badge | Meaning |
| --- | --- |
| SIMULATED (purple) | Produced by the simulation with made-up data. Nothing real happened. |
| REAL LAB (green) | A real operation ran on your computer, on throw-away practice files. |
| ACTIVE / PAUSED / SUBMITTED | State of your simulation. Only an *active* simulation can be changed. |
| UNLABELED / PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED | How sensitive a piece of data is, from not yet decided to most sensitive. |
| ALLOWED / BLOCKED / DENIED | ALLOWED: the action went through. BLOCKED: a rule stopped it. DENIED: the person had no permission or their account was disabled. |
| MONITOR / WARN / BLOCK | What a rule does when it matches: only record it, warn the user, or stop the action. |
| Alert | A message raised when a rule matches something worth a look. |
| True positive / Benign positive / False positive / Undetermined | Your decision on an alert: a real problem; correct match but legitimate work; the rule matched something it should not; the evidence cannot tell. |
| Case | Your investigation folder: linked evidence, notes, scope, actions and report. |
| Observation / Inference / Unknown | A note type: what the evidence shows; what you conclude from it; what you cannot tell. |
| Remediation | An action that changes the environment, such as disabling an account or removing a permission. It is checked right after you apply it (VERIFIED). |
| Control-validation replay | Re-running the day with a test copy of the person's account to prove your fix works. |
| Sim clock | The simulated date and time inside the story (UTC), not your real clock. |
| DLP | Data loss prevention: rules that stop sensitive data leaving the company. |

## Troubleshooting

| Problem | What to do |
| --- | --- |
| *Cannot reach the Threatready server* | The API is not running. Start it (see the README) or ask your administrator. |
| *Invalid input* when creating an account | Username: letters, digits, `. _ - + @` (an email works). Password: 10+ characters with upper- and lower-case letters and a digit. |
| Buttons are greyed out | The simulation is paused or submitted. Open **Simulation Workspace** and click **Resume**, or **Reset** to start a new attempt. |
| A page says *No active scenario workspace* | Start or pick a simulation in **Simulation Workspace**, or choose one in the **Active workspace** box at the top. |
| *Run control-validation replay* is greyed out | Run the business day once first. |
| No alerts appeared | Run the business day first. If you disabled the bulk-download rule, alerts for big downloads will not fire. |
| A remediation shows VERIFICATION FAILED | The change did not stick (for example the account was re-enabled). Click **Re-verify** after correcting it. |
| Too many login attempts | Wait one minute and try again. |
| I want to start over | **Reset** in Simulation Workspace keeps past results; each lab page has its own **Reset**. |

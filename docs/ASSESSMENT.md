# Assessment and competency model

Implemented in `backend/app/services/assessment.py`; the rubric itself lives in the scenario JSON. Scores are computed **only on the server**, only on submission, and only from persisted session state. No AI model participates in grading.

## Categories (configurable default weights — not an industry standard)

| Category | Weight | Criteria (points) |
|---|---|---|
| Technical correctness | 25 | Export labelled correctly (8) · other unlabeled/mislabelled assets correct (8) · excessive grant removed (9) |
| Detection and analysis | 25 | Exfiltration alerts = true positive (6) · legitimate activity recognised as benign/false positive (5) · ambiguous activity not over-concluded (4) · determination + subject supported by evidence (5) · severity per risk model (5) |
| Evidence quality | 20 | Case links download event, transfer event and access path (8) · observation cites evidence + inference + unknown recorded (6) · exposure scope supported (6) |
| Remediation and validation | 20 | Validation replay shows exfiltration path closed (8) · legitimate activity still works in replay (5) · DLP independently blocks canonical exfiltration paths (4) · subject contained and verified (3) |
| Documentation and escalation | 10 | Escalated to Privacy Office or Legal (4) · report sections substantive and root causes identified, unsupported causes penalised (6) |

Category score = earned/available points in that category × weight. Total = sum (0–100). **Pass** = total ≥ 70 **and** no critical failure.

## Critical conditions (cannot be offset)

| Key | Condition |
|---|---|
| CF-EVIDENCE-DESTROYED | The subject's device was reimaged before evidence was preserved. |
| CF-NOT-VERIFIED | No control-validation replay exists, or the latest one shows the exfiltration path still open. |

If controls changed after the latest replay, “path closed” earns half credit (unverified change) and the *verify* task is shown as incomplete.

## Ambiguity and evidence-dependent truth

- The ambiguous after-hours download accepts BENIGN_POSITIVE or UNDETERMINED; concluding TRUE_POSITIVE is not rewarded because the evidence cannot support it.
- Determination, exposure status and record estimate are judged against what the run-1 events show (see docs/SCENARIOS.md).
- Subject identities must include the subject and must not include people the evidence does not implicate.

## Severity risk model (documented to learners, also available as a calculator)

`score = sensitivity (label rank 0–3; unknown = 2) + volume (≥10,000 records: 2; ≥1,000: 1) + external destination (2) + data left the organisation (YES 2 / UNKNOWN 1 / NO 0)`; ≥8 CRITICAL, 6–7 HIGH, 3–5 MEDIUM, ≤2 LOW. Exact match earns full points; one level off earns half.

## Outputs

Each attempt stores: total, pass flag, category scores, **per-criterion earned points with an explanation of each deduction**, critical failures, missing tasks, targeted lessons (criteria below 70 % map to curriculum lessons), mode label (“Guided practice result” vs “Independent assessment result”), and a SHA-256 **inputs digest** of every learner-controlled input. Identical state ⇒ identical score and digest (tested). A Markdown snapshot of the case report is stored with the attempt.

Every result states: *“Platform assessment outcome for the tasks in this scenario only. Not a professional certification.”*

## Guided vs independent

- **GUIDED**: learner may choose the variant (API) or receives a random one; progressive hints per task, recorded.
- **ASSESSMENT**: random variant, hints refused by the server (403).
- Reset after submission starts a new attempt (optionally a new variant); previous attempts are kept.

## Lesson completion

Lessons complete only from server-verified evidence: a scenario task done in any of the learner's sessions (remembered across resets), a passed lab exercise, a server-graded knowledge check (≥75 %, correct options never sent to the client), test-suite runs, change records, or a passed independent assessment (L5).

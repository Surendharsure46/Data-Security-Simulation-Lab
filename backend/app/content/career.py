"""Learning-journey content: welcome, platform overview, roles, Levels 0-5, missions and skills.

Journey (see docs/WORKFLOW.md):

    Welcome page -> Let's Get Started -> platform overview + choose a role -> sign up / sign in ->
    Level 0 .. Level 5, each = fundamentals (read) -> knowledge check (server-graded) ->
    hands-on lab missions (Understand -> Inspect -> Act -> Observe -> Validate -> Submit) ->
    server-side competency assessment -> pass: skills recorded / fail: skill gaps, remedial lesson, retry ->
    level complete -> congratulations popup -> next level unlocked automatically.

Content is data. Comprehension and knowledge-check answers never leave the server; skills and
required criteria refer to rubric criterion keys and lab exercise keys that already exist.
``validate_career_content`` cross-checks every reference at start-up and in tests.
"""
from __future__ import annotations

import random
from typing import Any

from .company import COMPANY, DEFAULT_LABELS, _luhn_complete

# Mission phases, in the order of the workflow diagram.
PHASES = [
    {"key": "UNDERSTAND", "title": "Understand Business Problem",
     "summary": "Read the request from the business and prove you understood what is at stake."},
    {"key": "INSPECT", "title": "Inspect Data, Events and Evidence",
     "summary": "Find the data, read the events and collect the evidence before acting."},
    {"key": "ACT", "title": "Perform Practical Actions",
     "summary": "Change the environment: classify, revoke, configure, contain."},
    {"key": "OBSERVE", "title": "Observe System Consequences",
     "summary": "Run the business and watch what your controls actually do."},
    {"key": "VALIDATE", "title": "Validate the Fix",
     "summary": "Prove the fix works without breaking legitimate business activity."},
    {"key": "SUBMIT", "title": "Submit Evidence and Explanation",
     "summary": "Explain what happened, what you did and how you know it worked, citing evidence."},
]
PHASE_KEYS = [p["key"] for p in PHASES]

# --------------------------------------------------------------------------- public welcome and platform overview

WELCOME = {
    "title": "Welcome to Data Security",
    "tagline": "Protect the information people trust you with — and learn it by doing the real work.",
    "intro": (
        "Every organisation runs on data: customer records, payroll, contracts, source code, health and payment "
        "information. Data security is the discipline of keeping that information confidential, accurate and available "
        "while the business uses it every day. It is not only about stopping attackers — most data loss starts with "
        "an over-shared folder, a forgotten export, a well-meaning employee or a misconfigured cloud bucket."
    ),
    "sections": [
        {"title": "The CIA triad",
         "points": ["Confidentiality — only the right people and systems can read the data.",
                    "Integrity — the data is accurate and has not been altered without authorisation.",
                    "Availability — the data is there when the business needs it, including after an incident."]},
        {"title": "The data lifecycle",
         "points": ["Create and classify → store and protect → use and share → archive → destroy.",
                    "Controls differ by stage: labels at creation, access control and encryption at rest, DLP when data is shared, retention and verified deletion at the end.",
                    "Most incidents happen at the 'share' stage, when data crosses a boundary its owner did not intend."]},
        {"title": "What goes wrong in practice",
         "points": ["Insiders moving bulk extracts to personal email or cloud storage.",
                    "Excessive permissions inherited through groups that nobody reviews.",
                    "Cloud storage left public, unencrypted or shared with forgotten accounts.",
                    "Sensitive data pasted into unapproved AI assistants.",
                    "Weak encryption settings, keys stored next to the data and backups never tested."]},
        {"title": "What data security professionals do",
         "points": ["Discover and classify sensitive data and give it an owner.",
                    "Design, test and tune controls such as access reviews, DLP, encryption and masking.",
                    "Investigate alerts with evidence, contain incidents and fix the root cause.",
                    "Prove every fix works — without breaking legitimate business activity."]},
    ],
    "motivation": [
        {"title": "Learn by doing", "text": "Every level ends with hands-on labs: real cryptography, a real SQL database and a full enterprise simulation."},
        {"title": "Safe to fail", "text": "Everything runs on synthetic data in your private copy of a fictional company. Mistakes teach, they never harm."},
        {"title": "Evidence-based progress", "text": "Your work is assessed on the server from what you actually changed. Passing records the skills you demonstrated."},
        {"title": "From beginner to mastery", "text": "Six levels take you from your first sensitive record to leading an incident end to end."},
    ],
}

PLATFORM = {
    "title": "How Threatready works",
    "summary": ("Threatready is a guided data-security training lab. You join Kestrel Ridge Financial, a fictional consumer-finance "
                "company, and progress through six levels. Each level teaches the fundamentals and then lets you practise them "
                "in interactive labs with step-by-step instructions."),
    "loop": [
        {"title": "Learn the fundamentals", "text": "Short lessons explain the concepts you need for the level."},
        {"title": "Check your knowledge", "text": "A short server-graded check confirms you are ready for the labs."},
        {"title": "Complete hands-on labs", "text": "Guided lab sessions: understand the problem, inspect, act, observe the consequences, validate the fix."},
        {"title": "Submit and get assessed", "text": "Explain what you did and why. The server grades your actual results and shows any skill gaps."},
        {"title": "Level up", "text": "Finish every lab in the level to unlock the next one automatically."},
    ],
    "safety": [
        "All companies, people and records are synthetic. Simulated activity never touches a real system.",
        "Every result is labelled SIMULATED or REAL_LAB (a real operation in your isolated local lab).",
        "Assessment results describe the tasks in this platform only. They are not a professional certification.",
    ],
}

ROLES = [
    {"key": "foundation", "title": "Data Security Generalist", "icon": "compass",
     "summary": "Not sure yet? Get a balanced grounding in every area before you specialise.",
     "focus": ["data-classification", "access-governance", "encryption", "privacy-governance"]},
    {"key": "soc-analyst", "title": "Data Security SOC Analyst", "icon": "radar",
     "summary": "Triage alerts, investigate with evidence, contain incidents and write the report.",
     "focus": ["alert-triage", "evidence-analysis", "incident-scoping", "containment", "escalation-reporting"]},
    {"key": "dlp-engineer", "title": "DLP Engineer", "icon": "shield",
     "summary": "Build, test and tune data-loss-prevention policies that stop leaks without blocking the business.",
     "focus": ["dlp-engineering", "control-validation", "data-classification", "ai-data-security"]},
    {"key": "data-protection-engineer", "title": "Data Protection Engineer", "icon": "lock",
     "summary": "Engineer encryption, key management, database and cloud controls that protect data at rest.",
     "focus": ["encryption", "database-security", "cloud-security", "access-governance"]},
]
ROLE_KEYS = [r["key"] for r in ROLES]

# Title prefix per level: Level 0 Trainee -> Level 5 Principal.
RANKS = ["Trainee", "Junior", "", "Senior", "Lead", "Principal"]


def role_title(role_key: str | None, level: int) -> str:
    role = next((r for r in ROLES if r["key"] == role_key), ROLES[0])
    return f"{RANKS[level]} {role['title']}".strip()


# --------------------------------------------------------------------------- organisation briefing (Level 0 fundamentals)

ORGANIZATION = {
    "company": COMPANY,
    "mission_statement": "Help everyday customers borrow and pay safely, and keep their data out of the wrong hands.",
    "crown_jewels": [
        {"name": "Customer master data", "where": "CRM and nightly CSV extracts on the support file share",
         "why": "Names, contact details and payment card numbers for 48,000+ customers."},
        {"name": "Payroll and HR records", "where": "Finance share and HR system",
         "why": "Bank details and national identifiers of employees."},
        {"name": "Integration secrets", "where": "IT configuration files", "why": "API keys that unlock customer systems."},
    ],
    "departments": [
        {"name": "Customer Operations", "note": "Runs support with in-house agents and contract agents from HelpWise."},
        {"name": "Finance", "note": "Sends payroll to the PayBridge provider every month."},
        {"name": "IT", "note": "Operates the CRM, file shares and the nightly export job."},
        {"name": "Security", "note": "Data Protection and the SOC. You join here."},
        {"name": "Legal and Privacy Office", "note": "Decide notification and regulatory obligations."},
        {"name": "Marketing", "note": "Publishes brochures and works with external print shops."},
    ],
    "team": [
        {"name": "Morgan Ellery", "role": "Head of Data Protection (your manager)", "note": "Assigns your labs and reviews your submissions."},
        {"name": "Priya Harris", "role": "Data Protection Analyst (your mentor)", "note": "Knows where the data lives and which controls are only piloted."},
        {"name": "Sam Fernandez", "role": "SOC Analyst", "note": "Your partner for alerts and investigations."},
        {"name": "Kai Wright", "role": "Senior Counsel, Legal", "note": "Escalate personal-data incidents here."},
    ],
    "current_concerns": [
        "Internal Audit found that bulk customer extracts are created nightly and nobody has reviewed who can read them.",
        "Several DLP rules still run in monitor-only pilot mode.",
        "The company is starting to use AI assistants and cloud storage without a clear data-handling standard.",
    ],
    "disclaimer": "Kestrel Ridge Financial and every person, record and domain in it are fictional.",
}

# --------------------------------------------------------------------------- interactive demo lab (Level 0)


def _demo_record() -> str:
    rng = random.Random(20260309)
    card = _luhn_complete("4", 16, rng)
    return (
        "customer_id,full_name,email,card_number,city\n"
        f"C-100482,Avery Lockhart,avery.lockhart@mail.example,{card[:4]} {card[4:8]} {card[8:12]} {card[12:]},Austin\n"
    )


DEMO = {
    "title": "Interactive Demo",
    "intro": ("Try the three moves you will repeat in every lab on a single synthetic customer record: inspect the data, "
              "decide how sensitive it is, then see what the DLP control does when someone tries to send it."),
    "record_name": "support_ticket_attachment.csv",
    "record": _demo_record(),
    "labels": [{k: lab[k] for k in ("key", "name", "rank", "description")} for lab in DEFAULT_LABELS],
    "expected_label": "restricted",
    "label_feedback": {
        "public": "Public data can be released to anyone. This record holds a payment card number, so it is far from public.",
        "internal": "Internal fits routine staff information. A payment card number with a named customer is regulated data.",
        "confidential": "Close. Personal data alone would be Confidential, but payment card numbers make it Restricted in this label scheme.",
        "restricted": "Correct. Payment card numbers tied to a named customer are Restricted under the company label scheme.",
    },
    "destinations": [
        {"key": "dst-personal-webmail", "name": "Personal webmail (mail.example)", "category": "PERSONAL", "kind": "EMAIL",
         "sanctioned": False, "internal": False},
        {"key": "dst-helpwise-sftp", "name": "HelpWise vendor SFTP (contracted partner)", "category": "SANCTIONED_PARTNER",
         "kind": "SFTP", "sanctioned": True, "internal": False},
        {"key": "dst-internal-email", "name": "Internal email to a colleague", "category": "INTERNAL", "kind": "EMAIL",
         "sanctioned": True, "internal": True},
    ],
    "policy": {
        "name": "Block classified customer data to unsanctioned destinations",
        "description": "Demo policy: Confidential or higher data, or content containing payment cards, may not leave to unsanctioned destinations.",
        "kind": "DLP", "priority": 10, "applies_to_actions": ["EMAIL", "UPLOAD"],
        "conditions": {"match": "all", "conditions": [
            {"field": "destination.sanctioned", "op": "eq", "value": False},
            {"match": "any", "conditions": [
                {"field": "content.label", "op": "label_at_least", "value": "confidential"},
                {"field": "content.detected_types", "op": "contains_any", "value": ["CREDIT_CARD"]},
            ]},
        ]},
        "outcome": "BLOCK", "severity": "HIGH", "alert": True,
        "alert_title": "Blocked customer data to unsanctioned destination",
    },
    "completion": ["scanned", "classified", "observed_block", "observed_allow"],
}

# --------------------------------------------------------------------------- skills

SKILLS: dict[str, dict[str, Any]] = {
    "data-classification": {"name": "Data discovery & classification",
                            "description": "Finds sensitive data and assigns justified labels and owners.", "lessons": ["M01-L3", "M01-L4"]},
    "access-governance": {"name": "Access governance",
                          "description": "Reviews who can read sensitive data and removes excessive access.", "lessons": ["M01-L5", "M04-L1"]},
    "alert-triage": {"name": "Alert triage",
                     "description": "Separates true positives, benign activity and undetermined alerts.", "lessons": ["M07-L1", "M02-L5"]},
    "evidence-analysis": {"name": "Evidence-based analysis",
                          "description": "Links events, separates observations from inferences and supports conclusions.", "lessons": ["M07-L2"]},
    "incident-scoping": {"name": "Incident scoping & severity",
                         "description": "Determines exposure scope and severity with the documented risk model.", "lessons": ["M07-L3"]},
    "dlp-engineering": {"name": "DLP policy engineering",
                        "description": "Builds and tunes DLP policies that stop data loss without disrupting the business.",
                        "lessons": ["M02-L2", "M02-L3", "M02-L4"]},
    "control-validation": {"name": "Control validation",
                           "description": "Proves fixes by replaying activity against the changed controls.", "lessons": ["M08-L3", "M08-L2"]},
    "containment": {"name": "Containment", "description": "Contains a subject proportionately and verifies the containment.",
                    "lessons": ["M07-L4"]},
    "escalation-reporting": {"name": "Escalation & reporting",
                             "description": "Escalates to the right parties and writes evidence-based reports.", "lessons": ["M07-L5", "M05-L1"]},
    "encryption": {"name": "Encryption & key management",
                   "description": "Uses hashing, authenticated encryption and envelope keys correctly.",
                   "lessons": ["M03-L1", "M03-L2", "M03-L3", "M03-L4", "M03-L5"]},
    "database-security": {"name": "Database security",
                          "description": "Applies least privilege, parameterised queries, masking, auditing and verified restores.",
                          "lessons": ["M04-L1", "M04-L2", "M04-L3", "M04-L4", "M04-L5"]},
    "privacy-governance": {"name": "Privacy & data governance", "description": "Applies minimisation, retention and verified deletion.",
                           "lessons": ["M05-L2", "M05-L3", "M05-L4"]},
    "cloud-security": {"name": "Cloud data security", "description": "Assesses and reduces cloud storage exposure.",
                       "lessons": ["M06-L1", "M06-L2"]},
    "ai-data-security": {"name": "AI data security", "description": "Controls prompts, retrieval permissions and AI logs.",
                         "lessons": ["M09-L1", "M09-L2", "M09-L3"]},
}

CRITERION_SKILLS = {
    "TC-LABEL-EXPORT": "data-classification", "TC-LABEL-INVENTORY": "data-classification", "TC-EXCESSIVE-GRANT": "access-governance",
    "DA-TRUE-POSITIVE": "alert-triage", "DA-BENIGN": "alert-triage", "DA-AMBIGUOUS": "alert-triage",
    "DA-DETERMINATION": "evidence-analysis", "DA-SEVERITY": "incident-scoping", "EQ-EVIDENCE": "evidence-analysis",
    "EQ-NOTES": "evidence-analysis", "EQ-SCOPE": "incident-scoping", "RV-PATH-CLOSED": "control-validation",
    "RV-NO-DISRUPTION": "dlp-engineering", "RV-DLP-DEPTH": "dlp-engineering", "RV-CONTAINMENT": "containment",
    "DE-ESCALATION": "escalation-reporting", "DE-REPORT": "escalation-reporting",
}

LAB_ROUTES = {"encryption": "/labs/encryption", "database": "/labs/database", "privacy": "/labs/privacy",
              "cloud": "/labs/cloud", "ai": "/labs/ai"}
LAB_SKILLS = {"encryption": "encryption", "database": "database-security", "privacy": "privacy-governance",
              "cloud": "cloud-security", "ai": "ai-data-security"}
EXERCISE_LESSONS = {
    ("encryption", "hashing"): "M03-L1", ("encryption", "file_roundtrip"): "M03-L2",
    ("encryption", "envelope_rotation"): "M03-L3", ("encryption", "tls_metadata"): "M03-L4",
    ("encryption", "config_review"): "M03-L5",
    ("database", "least_privilege"): "M04-L1", ("database", "injection"): "M04-L2", ("database", "masking"): "M04-L3",
    ("database", "audit"): "M04-L4", ("database", "backup_restore"): "M04-L5",
    ("privacy", "minimization"): "M05-L2", ("privacy", "retention"): "M05-L3", ("privacy", "report"): "M05-L4",
    ("cloud", "assess"): "M06-L1", ("cloud", "remediate"): "M06-L2",
    ("ai", "prompt_gateway"): "M09-L1", ("ai", "rag_acl"): "M09-L2", ("ai", "retention"): "M09-L3",
}

# Step-by-step instructions for every lab exercise (shown in the guided lab session).
EXERCISE_STEPS: dict[tuple[str, str], list[str]] = {
    ("encryption", "hashing"): [
        "Read the published SHA-256 manifest for the original payroll batch.",
        "Click 'Compute SHA-256' for each of the three payroll files.",
        "One file shows MISMATCH — it was altered in transit.",
        "Choose that file in 'which file was modified?' and click 'Submit answer'."],
    ("encryption", "file_roundtrip"): [
        "Type a lab-only passphrase of 12+ characters and click 'Encrypt'.",
        "Change one character of the passphrase and click 'Decrypt with this passphrase' — it must be rejected.",
        "Restore the correct passphrase and decrypt again — the plaintext must match the original.",
        "Click 'Tamper with ciphertext', then decrypt with the correct passphrase — authenticated encryption must reject it."],
    ("encryption", "envelope_rotation"): [
        "Click '1. Initialise' to encrypt the backup with a data key wrapped by a key-encryption key.",
        "Click '2. Rotate KEK'. Notice the bulk ciphertext does not change.",
        "Click '3. Decrypt (active KEK)' to prove the data still decrypts.",
        "Optional: try the retired kek-v1 to see why old keys are retired."],
    ("encryption", "tls_metadata"): [
        "Read the captured TLS 1.3 records.",
        "Tick everything a passive network observer can still see.",
        "Click 'Check answer' and adjust until it passes."],
    ("encryption", "config_review"): [
        "Fix the weak settings: minimum TLS version, at-rest algorithm, key location, secret storage, rotation period, certificate verification, backup encryption and cipher suites.",
        "Click 'Save & validate'.",
        "Repeat until the validator reports no findings."],
    ("database", "audit"): [
        "Open the 'Audit log' tab.",
        "Look for a support role returning hundreds of rows in a single query.",
        "Click 'Flag as suspicious' on that entry."],
    ("database", "least_privilege"): [
        "Open 'Least privilege' and find the grant that gives support_agent the full customers table.",
        "Click 'Revoke' on that grant.",
        "In 'Test as a role', run SELECT * FROM customers as support_agent — it must be DENIED.",
        "Run SELECT * FROM customers_masked LIMIT 5 as support_agent — support must still be able to work."],
    ("database", "injection"): [
        "Open 'SQL injection' and keep the input  x' OR '1'='1 .",
        "Click 'Run vulnerable lookup' — string concatenation returns many rows.",
        "Click 'Run parameterised lookup' — the bound value returns nothing."],
    ("database", "masking"): [
        "Open 'Masking' and tick card_number, email and dob.",
        "Click 'Query customers_masked as support_agent' and confirm the values are masked."],
    ("database", "backup_restore"): [
        "Open 'Backup & restore'.",
        "Click 1. Back up → 2. Simulate damaging script → 3. Restore latest backup.",
        "Click 4. Verify — row counts and checksum must match."],
    ("privacy", "minimization"): [
        "Read the documented purpose.",
        "For each field choose KEEP or REMOVE and give a reason.",
        "Click 'Submit decisions' and adjust until they are accepted."],
    ("privacy", "retention"): [
        "Set the inactivity and no-consent periods from the records standard; keep 'Legal hold overrides deletion' ticked.",
        "Click 'Evaluate (dry run)' and check that no held record would be deleted.",
        "Click 'Execute deletion'."],
    ("privacy", "report"): ["After the other two exercises, click 'Generate report' and read the findings."],
    ("cloud", "assess"): [
        "Click 'Run assessment' and read each bucket's exposure score.",
        "Choose the highest-exposure bucket of the original estate and click 'Submit'."],
    ("cloud", "remediate"): [
        "Reduce exposure: change access, remove cross-account principals, enable encryption and logging where needed.",
        "Keep every documented business requirement working.",
        "Run a fresh assessment after your last change, then click 'Verify'."],
    ("ai", "prompt_gateway"): [
        "Open 'Prompt gateway'. Edit the policy so sensitive prompts to the unapproved AI are blocked and card, bank and secret data is blocked everywhere.",
        "Click 'Save & evaluate prompts' until every prompt in the test set is handled correctly."],
    ("ai", "rag_acl"): [
        "Open 'Permission-aware retrieval' and enable 'Enforce source-document permissions'.",
        "Click 'Run access tests' until every test passes."],
    ("ai", "retention"): [
        "Open 'AI logging & retention'. Minimise prompt logging, shorten retention, restrict who can read logs and opt out of vendor training.",
        "Click 'Save & check' until no findings remain."],
}

DEMO_STEPS = [
    {"key": "scanned", "phase": "INSPECT", "title": "Inspect the record with the discovery detectors",
     "steps": ["Click 'Run discovery detectors'.", "Read which detectors matched and notice the evidence is masked."]},
    {"key": "classified", "phase": "ACT", "title": "Choose the correct classification label",
     "steps": ["Compare the record with the four label definitions.", "Choose a label and click 'Apply label'. Read the feedback."]},
    {"key": "observed_block", "phase": "OBSERVE", "title": "Try a transfer the policy should stop",
     "steps": ["Click 'Send to Personal webmail'.", "Open 'Why?' to read the policy trace."]},
    {"key": "observed_allow", "phase": "VALIDATE", "title": "Try a legitimate transfer that must keep working",
     "steps": ["Click 'Send to HelpWise vendor SFTP (contracted partner)'.", "A good control stops leaks without blocking real work."]},
]

# --------------------------------------------------------------------------- missions (hands-on labs)

REF = "customer-data-export"


def _lab(level: int, mid: str, title: str, lab: str, exercises: list[tuple[str, str, str]], bp: dict, by: str = "Morgan Ellery, Head of Data Protection",
         min_explanation: int = 80) -> dict:
    return {"kind": "LAB", "level": level, "title": title, "assigned_by": by, "lab": lab, "min_explanation": min_explanation,
            "exercises": [{"exercise": e, "phase": ph, "title": t, "steps": EXERCISE_STEPS[(lab, e)]} for e, ph, t in exercises],
            "business_problem": bp}


MISSIONS: dict[str, dict[str, Any]] = {
    # ------------------------------------------------------------------ Level 0
    "MSN-001": {
        "kind": "DEMO", "level": 0, "title": "Your first data protection move", "assigned_by": "Priya Harris, Data Protection Analyst (mentor)",
        "min_explanation": 40, "items": DEMO_STEPS,
        "business_problem": {
            "statement": ("A support agent attached a customer record to a ticket and wants to email it out. Before anything leaves the "
                          "company, inspect the record, decide how sensitive it is and see what the DLP control does."),
            "stakes": ["A real customer's payment card number", "Support must still be able to work with partners"],
            "success_looks_like": ["You identified the sensitive data", "You chose the correct label",
                                   "You saw a leak blocked and a legitimate transfer allowed"],
            "questions": [
                {"q": "What should you do first with a file you have never seen before?",
                 "options": ["Send it on", "Inspect what data it contains", "Delete it", "Encrypt it and forget it"], "answer": 1},
                {"q": "A good data-loss control should…",
                 "options": ["Block everything", "Stop leaks while legitimate business transfers keep working",
                             "Only send reports", "Allow everything"], "answer": 1},
            ]},
    },
    "MSN-002": _lab(0, "MSN-002", "Spot the tampered payroll file", "encryption",
                    [("hashing", "INSPECT", "Find the altered file by comparing SHA-256 hashes")],
                    {"statement": ("Finance received three copies of the payroll batch and one was altered in transit. Use hashing "
                                   "to find out which copy cannot be trusted before payments go out."),
                     "stakes": ["Employees paid to the wrong account", "Silent tampering with payment files"],
                     "success_looks_like": ["The altered file is identified by its hash"],
                     "questions": [
                         {"q": "A hash comparison tells you…", "options": ["Who changed the file", "Whether the file content changed",
                                                                         "The encryption key", "The file owner"], "answer": 1},
                         {"q": "If two files have the same SHA-256 hash, they…",
                          "options": ["Have the same content (for practical purposes)", "Have the same owner", "Are encrypted", "Are both malicious"], "answer": 0}]},
                    min_explanation=40),
    # ------------------------------------------------------------------ Level 1
    "MSN-101": {
        "kind": "SCENARIO", "level": 1, "title": "Find and protect the customer export", "assigned_by": "Morgan Ellery, Head of Data Protection",
        "scenario_id": REF, "mode": "GUIDED", "min_score": 70,
        "business_problem": {
            "statement": ("Internal Audit found a nightly extract of every customer on the support file share. Nobody owns it, "
                          "nobody has reviewed who can read it and the DLP rule for cloud uploads is still in pilot. Today is a "
                          "normal business day. Make sure the extract cannot leave the company and handle anything that happens."),
            "stakes": ["48,000+ customers' card numbers and contact details", "Regulatory notification if data leaves the company",
                       "Support and payroll transfers must keep working"],
            "success_looks_like": ["The extract is classified and has an owner", "Excessive access is removed",
                                   "A replay of the day proves the exfiltration path is closed", "Your explanation is backed by cited evidence"],
            "questions": [
                {"q": "What is the most sensitive element of the customer extract?",
                 "options": ["City names", "Payment card numbers linked to named customers", "Customer IDs", "The file name"], "answer": 1},
                {"q": "Which outcome would NOT count as a successful mission?",
                 "options": ["Blocking customer data to personal destinations", "Blocking the monthly payroll submission to the contracted provider",
                             "Removing contractor access to bulk extracts", "Replaying the day to prove the fix"], "answer": 1},
                {"q": "Why does monitor-only DLP not solve the problem on its own?",
                 "options": ["It records the transfer but does not stop it", "It deletes the file", "It disables the user", "It encrypts the data"], "answer": 0},
            ]},
        "required_criteria": [{"criterion": "TC-LABEL-EXPORT", "min_fraction": 1.0}, {"criterion": "RV-PATH-CLOSED", "min_fraction": 1.0}],
    },
    "MSN-102": _lab(1, "MSN-102", "Prove file encryption actually protects data", "encryption",
                    [("file_roundtrip", "VALIDATE", "Encrypt with AES-256-GCM; prove a wrong passphrase and tampering are rejected")],
                    {"statement": ("Finance wants to send encrypted payroll archives and asks whether 'encrypted' really means protected. "
                                   "Prove that encryption rejects the wrong key and any tampering."),
                     "stakes": ["Employee bank details in payroll archives", "Undetected modification of payment files"],
                     "success_looks_like": ["Wrong passphrases are rejected", "Tampered ciphertext is rejected", "The right key restores identical data"],
                     "questions": [
                         {"q": "Authenticated encryption (AES-GCM) should react to a tampered ciphertext by…",
                          "options": ["Decrypting it anyway", "Refusing to decrypt", "Re-encrypting it", "Deleting the key"], "answer": 1},
                         {"q": "Keys derived from passwords need…", "options": ["No salt", "A slow KDF and a random salt", "To be emailed", "Base64"], "answer": 1}]}),
    "MSN-103": _lab(1, "MSN-103", "Close the support database gaps", "database",
                    [("least_privilege", "ACT", "Revoke the excessive grant and prove the role is denied"),
                     ("injection", "VALIDATE", "Show injection works on the vulnerable lookup and fails on the parameterised one")],
                    {"statement": ("The support database role can read more than support needs and a legacy lookup builds SQL from user "
                                   "input. Remove the excess privilege and prove the lookup is safe."),
                     "stakes": ["Bulk customer reads by a support role", "SQL injection exposing every row"],
                     "success_looks_like": ["The support role is denied the table it does not need", "The parameterised lookup resists injection"],
                     "questions": [
                         {"q": "Least privilege means a role gets…", "options": ["Every table, to avoid tickets", "Only what its work needs",
                                                                              "Read access to everything", "Admin rights during incidents"], "answer": 1},
                         {"q": "Parameterised queries stop SQL injection because…",
                          "options": ["They encrypt the input", "Input is sent as a value and never parsed as SQL", "They block long input", "They log every query"], "answer": 1}]},
                    by="Priya Harris, Data Protection Analyst"),
    # ------------------------------------------------------------------ Level 2
    "MSN-201": {
        "kind": "SCENARIO", "level": 2, "title": "Handle an exfiltration incident without help", "assigned_by": "Morgan Ellery, Head of Data Protection",
        "scenario_id": REF, "mode": "ASSESSMENT", "min_score": 75,
        "business_problem": {
            "statement": ("Another business day, another bulk extract — and this time you are on your own. No hints, and the subject and "
                          "channel may differ from anything you have seen. Investigate, contain, fix and prove it."),
            "stakes": ["A customer extract may leave the company today", "Wrongly accusing an employee", "Missing a notification deadline"],
            "success_looks_like": ["Your case links the download, the transfer and the access path", "Determination and subject are supported by evidence",
                                   "The incident is escalated to Privacy Office or Legal", "A replay proves the path is closed"],
            "questions": [
                {"q": "An after-hours bulk download with an unverifiable ticket should be dispositioned…",
                 "options": ["As a true positive — it looks suspicious", "Only as far as the evidence supports, e.g. undetermined", "Ignored",
                             "As a false positive by default"], "answer": 1},
                {"q": "Who should decide notification obligations for a personal-data incident?",
                 "options": ["The SOC analyst alone", "Legal / Privacy Office", "The vendor", "Nobody"], "answer": 1},
                {"q": "Disabling the subject's account proves that…",
                 "options": ["The control gap is closed for everyone", "That one account is contained — the gap may remain",
                             "No data left the company", "Evidence was preserved"], "answer": 1},
            ]},
        "required_criteria": [{"criterion": "EQ-EVIDENCE", "min_fraction": 1.0}, {"criterion": "DA-DETERMINATION", "min_fraction": 1.0},
                              {"criterion": "DE-ESCALATION", "min_fraction": 1.0}, {"criterion": "RV-PATH-CLOSED", "min_fraction": 1.0}],
    },
    "MSN-202": _lab(2, "MSN-202", "Find the bulk reader in the audit log", "database",
                    [("audit", "INSPECT", "Identify the suspicious bulk query in the database audit log")],
                    {"statement": "Someone using the support role pulled far more customer rows than support work needs. Find the entry in the audit log.",
                     "stakes": ["Undetected bulk access to customer data"],
                     "success_looks_like": ["The bulk query is flagged"],
                     "questions": [
                         {"q": "Which audit entry is most suspicious for a support role?",
                          "options": ["One customer looked up by ID", "Hundreds of rows returned by one query", "A failed login", "A schema change by the DBA"], "answer": 1},
                         {"q": "Audit logs are useful because they record…",
                          "options": ["Who queried what and how many rows came back", "Only errors", "Passwords", "Nothing useful"], "answer": 0}]},
                    by="Sam Fernandez, SOC Analyst"),
    # ------------------------------------------------------------------ Level 3
    "MSN-301": _lab(3, "MSN-301", "Mask sensitive columns and prove you can recover", "database",
                    [("masking", "ACT", "Enable masking so the support role sees only masked values"),
                     ("backup_restore", "VALIDATE", "Back up, damage, restore and verify the lab database")],
                    {"statement": ("Support agents see full card numbers they never need, and nobody has ever tested a restore. Reduce what "
                                   "support can see and prove the database can be recovered."),
                     "stakes": ["Card numbers visible to every agent", "Unrecoverable data after an incident"],
                     "success_looks_like": ["Support sees masked values only", "A restore is verified by counts and checksums"],
                     "questions": [
                         {"q": "Masking a column…", "options": ["Encrypts the base table", "Limits what a role sees; the base table is unchanged",
                                                             "Deletes the data", "Replaces backups"], "answer": 1},
                         {"q": "A backup is proven by…", "options": ["Its file size", "A verified restore", "Its timestamp", "Its name"], "answer": 1}]},
                    by="Priya Harris, Data Protection Analyst"),
    "MSN-302": _lab(3, "MSN-302", "Rotate keys and harden the encryption configuration", "encryption",
                    [("envelope_rotation", "ACT", "Rotate the key-encryption key and verify data still decrypts"),
                     ("config_review", "VALIDATE", "Remediate the configuration until the validator reports no findings")],
                    {"statement": ("An external review flagged keys stored beside data, no key rotation and weak settings. Demonstrate rotation "
                                   "without re-encrypting every file and fix the configuration."),
                     "stakes": ["Keys compromised together with the data", "Interceptable legacy protocols"],
                     "success_looks_like": ["KEK rotated with data still decryptable", "Configuration validator reports no findings"],
                     "questions": [
                         {"q": "Rotating a KEK in envelope encryption…", "options": ["Re-encrypts all data", "Re-wraps data keys only",
                                                                                  "Deletes old data", "Disables TLS"], "answer": 1},
                         {"q": "Where should production keys live?", "options": ["Next to the data", "In a KMS or HSM", "In source code", "In email"], "answer": 1}]}),
    "MSN-303": {
        "kind": "SCENARIO", "level": 3, "title": "Engineer the fix without breaking the business", "assigned_by": "Morgan Ellery, Head of Data Protection",
        "scenario_id": REF, "mode": "ASSESSMENT", "min_score": 80,
        "business_problem": {
            "statement": ("Last quarter a blunt block on personal cloud stopped Marketing's print-shop uploads and payroll alerts flooded the "
                          "SOC. This time the fix must stop customer data leaving through any personal channel, keep every legitimate "
                          "transfer working and treat benign activity as benign."),
            "stakes": ["Business disruption from over-blocking", "Alert fatigue from false positives", "Customer data loss"],
            "success_looks_like": ["DLP blocks customer data to personal cloud and personal webmail", "Every legitimate activity still succeeds in the replay",
                                   "Benign alerts are recognised as benign"],
            "questions": [
                {"q": "Blocking an entire personal-cloud domain would…",
                 "options": ["Be the ideal fix", "Also stop the legitimate brochure upload — business disruption", "Have no side effects",
                             "Improve recall without cost"], "answer": 1},
                {"q": "A narrow exception should be based on…",
                 "options": ["The user's name only", "A specific destination plus business context", "Time of day only", "File size only"], "answer": 1},
            ]},
        "required_criteria": [{"criterion": "RV-NO-DISRUPTION", "min_fraction": 1.0}, {"criterion": "RV-DLP-DEPTH", "min_fraction": 1.0},
                              {"criterion": "RV-PATH-CLOSED", "min_fraction": 1.0}, {"criterion": "DA-BENIGN", "min_fraction": 1.0}],
    },
    # ------------------------------------------------------------------ Level 4
    "MSN-401": _lab(4, "MSN-401", "Privacy review of the marketing dataset", "privacy",
                    [("minimization", "INSPECT", "Identify the fields the marketing purpose does not need"),
                     ("retention", "ACT", "Configure retention and delete expired records, respecting legal hold"),
                     ("report", "VALIDATE", "Generate the privacy findings report")],
                    {"statement": ("Marketing keeps everything forever 'just in case'. Legal wants the dataset minimised, expired records "
                                   "deleted (except those under legal hold) and a findings report."),
                     "stakes": ["Over-collection of personal data", "Deleting records under legal hold"],
                     "success_looks_like": ["Unneeded fields identified", "Only expired, non-held records deleted", "Findings report generated"],
                     "questions": [
                         {"q": "Data minimisation asks…", "options": ["Is this field needed for the purpose?", "Is the disk full?",
                                                                   "Is the data encrypted?", "Is the backup recent?"], "answer": 0},
                         {"q": "A record under legal hold that has passed its retention period should be…",
                          "options": ["Deleted immediately", "Kept until the hold is released", "Anonymised by marketing", "Emailed to Legal"], "answer": 1}]},
                    by="Kai Wright, Senior Counsel"),
    "MSN-402": _lab(4, "MSN-402", "Reduce cloud data exposure", "cloud",
                    [("assess", "INSPECT", "Assess the storage estate and identify the highest-exposure bucket"),
                     ("remediate", "VALIDATE", "Reduce total exposure below the target and re-assess")],
                    {"statement": ("Teams created cloud buckets faster than anyone reviewed them. Find the riskiest exposure, fix it and prove "
                                   "the estate is below the agreed risk target."),
                     "stakes": ["Publicly readable customer exports", "Cross-account access nobody remembers granting"],
                     "success_looks_like": ["Highest-exposure bucket identified", "Re-assessment below target"],
                     "questions": [
                         {"q": "Exposure combines…", "options": ["Bucket name and region", "Sensitivity, access configuration and activity",
                                                              "Object count only", "Storage cost"], "answer": 1},
                         {"q": "A remediation is proven by…", "options": ["Closing the ticket", "Re-assessing and seeing exposure drop",
                                                                       "Renaming the bucket", "Emailing the owner"], "answer": 1}]}),
    "MSN-403": _lab(4, "MSN-403", "Secure the AI assistant rollout", "ai",
                    [("prompt_gateway", "ACT", "Block confidential prompts to the unapproved AI while approved use continues"),
                     ("rag_acl", "VALIDATE", "Fix the retriever so support cannot retrieve HR documents"),
                     ("retention", "ACT", "Correct the AI logging and retention configuration")],
                    {"statement": ("Staff paste customer data into an unapproved chatbot and the internal assistant answers HR questions for "
                                   "anyone. Put guardrails in place before the company-wide rollout."),
                     "stakes": ["Customer data sent to an unapproved AI provider", "The assistant becoming a permission bypass"],
                     "success_looks_like": ["Confidential prompts to the unapproved AI are blocked", "Retrieval honours document permissions",
                                            "Prompt logs are minimised and retained briefly"],
                     "questions": [
                         {"q": "A prompt sent to an external AI service is…", "options": ["Not a data transfer", "A data transfer subject to DLP",
                                                                                       "Always anonymous", "Encrypted at rest by default"], "answer": 1},
                         {"q": "Permission-aware retrieval means…", "options": ["The assistant sees everything", "Results honour the requesting user's permissions",
                                                                             "Only admins can query", "Documents are public"], "answer": 1}]}),
    "MSN-404": _lab(4, "MSN-404", "What TLS still reveals", "encryption",
                    [("tls_metadata", "INSPECT", "Identify everything a passive observer can see in a TLS 1.3 session")],
                    {"statement": ("The architecture board assumes 'it's over TLS, so nobody can see anything'. Show exactly which "
                                   "metadata remains visible so the design can account for it."),
                     "stakes": ["Over-trusting transport encryption", "Leaking which services staff use"],
                     "success_looks_like": ["Every visible metadata item identified"],
                     "questions": [
                         {"q": "Which is visible to an observer of a TLS connection?", "options": ["The payload", "The server name (SNI) and sizes",
                                                                                                "The session key", "The password"], "answer": 1},
                         {"q": "TLS primarily protects…", "options": ["Data at rest", "Data in transit", "Backups", "Logs"], "answer": 1}]}),
    # ------------------------------------------------------------------ Level 5
    "MSN-501": {
        "kind": "SCENARIO", "level": 5, "title": "Lead the incident end to end", "assigned_by": "CISO office",
        "scenario_id": REF, "mode": "ASSESSMENT", "min_score": 85,
        "business_problem": {
            "statement": ("You are now the escalation point. Run the response from discovery to report on an unfamiliar variant with no "
                          "hints. The CISO expects every category of the work to be strong, not just the total."),
            "stakes": ["Board-level visibility", "Regulatory scrutiny of the report", "Credibility of the data protection programme"],
            "success_looks_like": ["Score of 85 or more with no critical failures", "At least 80% in every rubric category"],
            "questions": [
                {"q": "A report that states a cause the evidence does not support…",
                 "options": ["Is fine if plausible", "Is penalised — conclusions must be supported", "Improves the score", "Is required"], "answer": 1},
                {"q": "Before reimaging the subject's device you must…",
                 "options": ["Notify Marketing", "Preserve evidence", "Disable DLP", "Close the case"], "answer": 1},
            ]},
        "required_criteria": [{"category": c, "min_percent": 80} for c in ("technical", "detection", "evidence", "remediation", "documentation")],
    },
}

# --------------------------------------------------------------------------- level knowledge checks (answers never leave the server)

LEVEL_CHECKS: dict[int, list[dict[str, Any]]] = {
    0: [
        {"q": "Which three properties make up the CIA triad?", "options": ["Cost, Investment, Assurance", "Confidentiality, Integrity, Availability",
                                                                         "Control, Inspection, Audit", "Cloud, Identity, Access"], "answer": 1},
        {"q": "At which lifecycle stage do most data-loss incidents occur?", "options": ["Create", "Share", "Archive", "Destroy"], "answer": 1},
        {"q": "A MONITOR outcome in a DLP policy…", "options": ["Stops the transfer", "Records and may alert but allows the transfer",
                                                               "Deletes the file", "Disables the user"], "answer": 1},
        {"q": "Hashing differs from encryption because hashing is…", "options": ["Reversible with a key", "A one-way fingerprint used for integrity",
                                                                               "Only for passwords", "Always slower"], "answer": 1},
        {"q": "Who should confirm legal notification obligations after a personal-data incident?",
         "options": ["The SOC analyst alone", "Legal / Privacy Office", "The data subject", "The vendor"], "answer": 1},
    ],
    1: [
        {"q": "A detector match confirmed by a validator (e.g. Luhn) means…", "options": ["Certain sensitive data", "Higher confidence that still needs context",
                                                                                         "A false positive", "The file is encrypted"], "answer": 1},
        {"q": "Inherited folder permissions are a common source of…", "options": ["Encryption", "Excessive access", "Backups", "Faster queries"], "answer": 1},
        {"q": "Before rolling out a DLP policy you should test…", "options": ["Nothing", "A prohibited and a legitimate transfer",
                                                                            "Only the prohibited case", "Only on production"], "answer": 1},
        {"q": "Decryption with the wrong key or tampered ciphertext should…", "options": ["Succeed quietly", "Fail", "Return partial data", "Re-encrypt"], "answer": 1},
        {"q": "Concatenating user input into SQL allows…", "options": ["Faster lookups", "Input to become code (SQL injection)", "Masking", "Auditing"], "answer": 1},
    ],
    2: [
        {"q": "A benign positive means…", "options": ["The rule matched correctly but the activity is legitimate", "The rule is broken",
                                                     "The activity is malicious", "Nothing matched"], "answer": 0},
        {"q": "Correlation between events should rely on…", "options": ["Timing alone", "Explicit attributes such as actor, resource and transaction",
                                                                      "Gut feeling", "Alert colour"], "answer": 1},
        {"q": "An inference in a case note is…", "options": ["What an event literally shows", "A conclusion drawn from observations", "A log line", "A hint"], "answer": 1},
        {"q": "Before destructive device actions you must…", "options": ["Preserve evidence", "Close the case", "Notify marketing", "Disable DLP"], "answer": 0},
        {"q": "Bulk reads by a role that normally fetches single records are…", "options": ["Normal", "A strong signal worth investigating",
                                                                                             "Proof of guilt", "Irrelevant"], "answer": 1},
    ],
    3: [
        {"q": "Precision answers…", "options": ["Of everything flagged, how much was truly bad?", "Of everything bad, how much was flagged?",
                                                "How fast the rule runs", "How many rules exist"], "answer": 0},
        {"q": "A production rule change should include…", "options": ["Nothing", "Reason, expected impact, test evidence and a rollback plan",
                                                                     "Only a screenshot", "Approval from marketing"], "answer": 1},
        {"q": "A fix is proven when…", "options": ["The ticket is closed", "The replayed activity now fails safely and legitimate work continues",
                                                   "The user is warned", "A report is written"], "answer": 1},
        {"q": "Masking a database column…", "options": ["Encrypts the base table", "Limits what a role sees; the base table is unchanged",
                                                       "Deletes the data", "Replaces backups"], "answer": 1},
        {"q": "Rotating a key-encryption key in envelope encryption…", "options": ["Re-encrypts all data", "Re-wraps the data keys only",
                                                                                  "Deletes old data", "Disables TLS"], "answer": 1},
    ],
    4: [
        {"q": "Cloud exposure combines…", "options": ["Sensitivity, access configuration and activity", "Bucket name and region", "Object count only",
                                                     "Storage cost"], "answer": 0},
        {"q": "A prompt sent to an external AI service is…", "options": ["Not a data transfer", "A data transfer subject to DLP", "Always anonymous",
                                                                        "Encrypted at rest by default"], "answer": 1},
        {"q": "Retrieval systems (RAG) must enforce…", "options": ["The requesting user's source-document permissions", "Nothing", "Admin rights",
                                                                  "Public access"], "answer": 0},
        {"q": "Retention rules state…", "options": ["How long each category is kept", "Who owns the data", "Which cipher to use", "The backup size"], "answer": 0},
        {"q": "TLS leaves visible…", "options": ["The payload", "Metadata such as IPs, sizes, timing and usually the server name", "The keys",
                                                 "Nothing at all"], "answer": 1},
    ],
    5: [
        {"q": "An independent assessment differs from guided practice because…", "options": ["It has hints", "There are no hints and the variant is unpredictable",
                                                                                            "It is not graded", "It is shorter"], "answer": 1},
        {"q": "Critical failures in the rubric…", "options": ["Can be offset by high scores", "Cannot be offset by other scores", "Are optional",
                                                             "Only affect documentation"], "answer": 1},
        {"q": "A strong incident report states…", "options": ["Only conclusions", "What is known, how it is known, what is unknown and what was done and verified",
                                                             "Who to blame", "Nothing about unknowns"], "answer": 1},
        {"q": "Revoking a user's sessions alone…", "options": ["Stops them signing in again", "Does not stop them signing in again", "Deletes their data",
                                                              "Proves the fix"], "answer": 1},
        {"q": "Leading an incident means balancing…", "options": ["Speed only", "Containment, evidence, business continuity and escalation",
                                                                 "Blame and speed", "Nothing"], "answer": 1},
    ],
}

# --------------------------------------------------------------------------- Levels 0-5

LEVELS: list[dict[str, Any]] = [
    {"level": 0, "title": "Foundation", "icon": "seed",
     "summary": "Meet the company, learn the language of data security and make your first protective moves.",
     "before_you_start": ["No prior experience needed.", "Read the fundamentals at your own pace, then pass a 5-question check.",
                          "Your first labs are short and fully guided."],
     "responsibilities": ["Learn the vocabulary of data security", "Understand Kestrel Ridge's crown-jewel data",
                          "Spot sensitive data and tampered files"],
     "challenge": "Short guided labs with instant feedback.",
     "intro_items": [{"type": "briefing", "key": "briefing", "title": "Meet Kestrel Ridge Financial"}],
     "missions": ["MSN-001", "MSN-002"]},
    {"level": 1, "title": "Practitioner", "icon": "tools",
     "summary": "Discover and classify data, configure DLP, encrypt files and apply least privilege.",
     "before_you_start": ["You will work in your first full enterprise simulation.", "Guided mode: hints are available.",
                          "Plan about 2 hours across the three labs."],
     "responsibilities": ["Classify sensitive data and assign owners", "Review access to customer data", "Verify encryption and database basics"],
     "challenge": "Guided scenario with hints; real cryptography and SQL labs.",
     "intro_items": [], "missions": ["MSN-101", "MSN-102", "MSN-103"]},
    {"level": 2, "title": "Analyst", "icon": "search",
     "summary": "Triage alerts, investigate with evidence and handle an incident on your own.",
     "before_you_start": ["The scenario lab is an independent assessment: no hints and an unpredictable variant.",
                          "Evidence, a supported determination and escalation are mandatory."],
     "responsibilities": ["Investigate incidents without hints", "Escalate personal-data incidents", "Read audit logs for bulk access"],
     "challenge": "No hints, random variant; pass mark 75 plus required criteria.",
     "intro_items": [], "missions": ["MSN-201", "MSN-202"]},
    {"level": 3, "title": "Engineer", "icon": "gear",
     "summary": "Engineer controls that stop data loss without disrupting the business, and prove them.",
     "before_you_start": ["Precision matters as much as coverage.", "Every change must be proven by replay or verification."],
     "responsibilities": ["Tune DLP for precision", "Own key management and encryption configuration", "Mask data and verify restores"],
     "challenge": "Pass mark 80 and zero tolerance for business disruption.",
     "intro_items": [], "missions": ["MSN-301", "MSN-302", "MSN-303"]},
    {"level": 4, "title": "Architect", "icon": "layers",
     "summary": "Assess cross-domain exposure: privacy, cloud, AI and transport encryption.",
     "before_you_start": ["Four labs across privacy, cloud, AI and TLS.", "Each lab is verified against an explicit target state."],
     "responsibilities": ["Run privacy reviews", "Reduce cloud data exposure", "Set AI data-handling guardrails", "Account for TLS metadata in designs"],
     "challenge": "Broad, cross-domain labs with business constraints.",
     "intro_items": [], "missions": ["MSN-401", "MSN-402", "MSN-403", "MSN-404"]},
    {"level": 5, "title": "Mastery", "icon": "trophy",
     "summary": "Lead an incident end to end on an unfamiliar variant with no hints.",
     "before_you_start": ["One demanding lab: the full incident lifecycle, independently.", "Pass mark 85 with at least 80% in every rubric category."],
     "responsibilities": ["Lead incident response end to end", "Report to the CISO with evidence-backed conclusions"],
     "challenge": "Pass mark 85 and ≥ 80% in every category.",
     "intro_items": [{"type": "text", "key": "mastery", "title": "What mastery looks like",
                      "body": ("Mastery is not memorising answers. It is making supported decisions under uncertainty: preserving evidence "
                               "before acting, containing proportionately, fixing the root cause rather than the symptom, proving the fix "
                               "without disrupting legitimate work, and writing a report that separates what you know from what you infer.")}],
     "missions": ["MSN-501"]},
]
TOP_LEVEL = LEVELS[-1]["level"]
JOURNEY_COMPLETE = TOP_LEVEL + 1  # pending_promotion value meaning "all six levels complete"


def level_def(level: int) -> dict[str, Any] | None:
    return next((lv for lv in LEVELS if lv["level"] == level), None)


def check_id(level: int) -> str:
    return f"LEVEL-L{level}"


def validate_career_content() -> None:
    """Cross-check every reference. Raises ValueError on the first problem."""
    from ..routers.labs import LAB_EXERCISES
    from ..services.scenario_defs import get_definition
    from .curriculum import LESSONS

    lesson_ids = {x["id"] for x in LESSONS}
    for key, skill in SKILLS.items():
        for lesson in skill["lessons"]:
            if lesson not in lesson_ids:
                raise ValueError(f"Skill {key} references unknown lesson {lesson}")
    for role in ROLES:
        for sk in role["focus"]:
            if sk not in SKILLS:
                raise ValueError(f"Role {role['key']} references unknown skill {sk}")
    if [lv["level"] for lv in LEVELS] != list(range(6)) or len(RANKS) != 6:
        raise ValueError("Levels must be exactly 0..5")
    for lv in LEVELS:
        qs = LEVEL_CHECKS.get(lv["level"])
        if not qs or any(not 0 <= q["answer"] < len(q["options"]) for q in qs):
            raise ValueError(f"Level {lv['level']} knowledge check missing or invalid")
        if not any(x["level"] == f"L{lv['level']}" for x in LESSONS):
            raise ValueError(f"Level {lv['level']} has no fundamentals lessons")
    for lesson in EXERCISE_LESSONS.values():
        if lesson not in lesson_ids:
            raise ValueError(f"Exercise lesson {lesson} unknown")
    listed = [m for lv in LEVELS for m in lv["missions"]]
    if sorted(listed) != sorted(MISSIONS) or len(listed) != len(set(listed)):
        raise ValueError("Every mission must appear in exactly one level")
    for mid, m in MISSIONS.items():
        if level_def(m["level"]) is None or mid not in level_def(m["level"])["missions"]:
            raise ValueError(f"Mission {mid} level mismatch")
        for q in m["business_problem"]["questions"]:
            if not 0 <= q["answer"] < len(q["options"]):
                raise ValueError(f"Mission {mid} has an invalid answer index")
        if m["kind"] == "SCENARIO":
            d = get_definition(m["scenario_id"])
            if d is None:
                raise ValueError(f"Mission {mid} references unknown scenario {m['scenario_id']}")
            crit_keys = {c.key for c in d.rubric.criteria}
            for rc in m.get("required_criteria", []):
                if "criterion" in rc and rc["criterion"] not in crit_keys:
                    raise ValueError(f"Mission {mid} requires unknown criterion {rc['criterion']}")
                if "category" in rc and rc["category"] not in d.rubric.categories:
                    raise ValueError(f"Mission {mid} requires unknown category {rc['category']}")
            for c in d.rubric.criteria:
                if c.key not in CRITERION_SKILLS:
                    raise ValueError(f"Criterion {c.key} of {d.id} has no skill mapping")
            if m["mode"] not in ("GUIDED", "ASSESSMENT"):
                raise ValueError(f"Mission {mid} has invalid mode")
        elif m["kind"] == "LAB":
            if m["lab"] not in LAB_EXERCISES or m["lab"] not in LAB_ROUTES:
                raise ValueError(f"Mission {mid} references unknown lab {m['lab']}")
            for ex in m["exercises"]:
                if ex["exercise"] not in LAB_EXERCISES[m["lab"]]["exercises"]:
                    raise ValueError(f"Mission {mid} references unknown exercise {ex['exercise']}")
                if ex["phase"] not in PHASE_KEYS or ex["phase"] in ("UNDERSTAND", "SUBMIT"):
                    raise ValueError(f"Mission {mid} exercise {ex['exercise']} has invalid phase")
                if (m["lab"], ex["exercise"]) not in EXERCISE_LESSONS:
                    raise ValueError(f"Mission {mid} exercise {ex['exercise']} has no lesson")
        elif m["kind"] == "DEMO":
            if [i["key"] for i in m["items"]] != DEMO["completion"]:
                raise ValueError(f"Mission {mid} demo items must match the demo completion steps")
        else:
            raise ValueError(f"Mission {mid} has unknown kind {m['kind']}")

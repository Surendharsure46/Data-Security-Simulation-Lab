import { expect, test, type Page } from "@playwright/test";

// Full learner journey through the browser (spec section 21): welcome page -> Let's Get Started -> choose a role ->
// create an account -> My Journey -> Level 0 lesson reader, then the reference scenario in the practice sandbox:
// inspect and classify data, configure and test a policy, run the day, investigate, remediate, replay, submit,
// read the report, then reset and replay.

const PASSWORD = "E2e-Synthetic-Pass-42";
const ADMIN_PASSWORD = "E2e-Admin-Synthetic-42";  // bootstrap admin of the throw-away e2e backend (playwright.config.ts)

async function nav(page: Page, name: string) {
  const sidebar = page.getByRole("navigation", { name: "Primary" });
  const link = sidebar.getByRole("link", { name });
  if (!(await link.isVisible())) await sidebar.getByText(/^Tools · /).click();  // the tools section is collapsed
  await link.click();
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
}

async function toastOrResult(page: Page) {
  await page.waitForLoadState("networkidle");
}

test("reference scenario end to end", async ({ page }) => {
  page.on("dialog", (d) => d.accept());

  // 1. public welcome page with the call to action in the top-right corner
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "Welcome to Data Security" })).toBeVisible();
  await page.getByRole("banner").getByRole("link", { name: /Let.s Get Started/ }).click();

  // 2. platform overview, choose a role, create the account
  await expect(page.getByRole("heading", { level: 1, name: "How Threatready works" })).toBeVisible();
  await expect(page.getByText("Your path: Level 0 to Level 5")).toBeVisible();
  await page.getByRole("radio", { name: /Data Security SOC Analyst/ }).click();
  const user = `e2e${Date.now()}`;
  await page.locator('input[name="username"]').fill(user);
  await page.locator('input[name="display_name"]').fill("E2E Learner");
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole("button", { name: "Create account and start Level 0" }).click();

  // 2b. My Journey: role title, six levels, guided tour, next step opens the Level 0 lesson reader
  await expect(page.getByRole("heading", { level: 1, name: "Trainee Data Security SOC Analyst" })).toBeVisible();
  await page.getByRole("button", { name: "Skip tour" }).click();
  await expect(page.getByText("Level 5 · Mastery")).toBeVisible();
  await page.getByRole("button", { name: "Continue →" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Meet Kestrel Ridge Financial" })).toBeVisible();
  await page.getByRole("button", { name: /Got it — next lesson/ }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Data security and the data lifecycle" })).toBeVisible();
  await page.getByRole("link", { name: "My Journey" }).first().click();
  await expect(page.getByText("1/9 steps")).toBeVisible();

  // 2c. tools unlock level by level: at Level 0 only the Encryption Lab is open
  await expect(page.getByText(/Tools · 1\/\d+ unlocked/)).toBeVisible();
  await page.goto("/workspace");
  await expect(page.getByText(/Unlocks at/)).toBeVisible();
  await expect(page.getByText("Level 1", { exact: true }).first()).toBeVisible();

  // 2d. the free practice sandbox below needs Level 1 tools; continue as the bootstrap administrator (staff see every tool)
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.getByRole("banner").getByRole("link", { name: "Sign in" }).click();
  await page.locator('input[name="username"]').fill("admin");
  await page.locator('input[name="password"]').fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("radio", { name: /Data Security SOC Analyst/ }).click();
  await page.getByRole("button", { name: "Start my journey →" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Trainee Data Security SOC Analyst" })).toBeVisible();
  const skip = page.getByRole("button", { name: "Skip tour" });
  if (await skip.isVisible()) await skip.click();

  // 3. start the reference scenario (guided)
  await nav(page, "Simulation Workspace");
  await page.getByRole("button", { name: "Start guided practice" }).click();
  await expect(page.getByRole("heading", { name: "Unauthorized Customer-Data Export" })).toBeVisible();

  // 4. discover and inspect the export
  await nav(page, "Data Discovery");
  await page.getByRole("button", { name: "Run discovery scan" }).click();
  await expect(page.getByText(/Scan #1: \d+ findings/)).toBeVisible();
  await page.getByRole("row", { name: /Open customer_master_export_2026Q1.csv/ }).click();
  await expect(page.getByText("CREDIT_CARD").first()).toBeVisible();
  await expect(page.getByText("MISSING OWNER", { exact: true })).toBeVisible();

  // 5. classify it with an owner
  await nav(page, "Classification Studio");
  await page.getByRole("row", { name: /customer_master_export_2026Q1.csv/ }).click();
  await page.getByLabel("Label", { exact: true }).selectOption("restricted");
  await page.getByLabel("Data owner").selectOption("u-hpatel");
  await page.getByLabel("Justification").fill("Bulk customer PII with valid card numbers (HIGH confidence) and no owner");
  await page.getByRole("button", { name: "Save classification" }).click();
  await expect(page.getByText(/Saved: customer_master_export_2026Q1.csv/)).toBeVisible();

  // 6. configure a blocking DLP policy and save it
  await nav(page, "DLP Policy Studio");
  await page.getByRole("button", { name: "New policy" }).click();
  await page.getByLabel("Policy key").fill("POL-DLP-CUSTOMER");
  await page.getByLabel("Name").first().fill("Block classified data to unsanctioned destinations");
  await page.getByLabel("Outcome").first().selectOption("BLOCK");
  await page.getByRole("button", { name: "+ Condition" }).first().click(); // adds content.label label_at_least confidential
  await page.getByRole("button", { name: "Save policy" }).click();
  await expect(page.getByText("Created POL-DLP-CUSTOMER")).toBeVisible();

  // ...and test a prohibited and a legitimate transfer against saved policies
  await page.getByRole("tab", { name: "Test workspace" }).click();
  await page.getByRole("button", { name: "Test against saved policies" }).click();
  await expect(page.getByText(/Decision: BLOCK/)).toBeVisible();
  await page.getByLabel("Actor").selectOption("u-emorales");
  await page.getByLabel("Resource").selectOption("ast-product-brochure");
  await page.getByRole("button", { name: "Test against saved policies" }).click();
  await expect(page.getByText(/Decision: ALLOW/)).toBeVisible();

  // 7. execute the scenario
  await nav(page, "Simulation Workspace");
  await page.getByRole("button", { name: "Run business day" }).click();
  await expect(page.getByText(/Run 1: \d+ events, \d+ alerts, [1-9]\d* prevented/)).toBeVisible();

  // 8. inspect the resulting alerts and triage them
  await nav(page, "Incident Investigation");
  const rows = page.locator("table tbody tr.selectable");
  await expect(rows.first()).toBeVisible();
  const exportRow = rows.filter({ hasText: "customer_master_export" }).first();
  const subjectName = ((await exportRow.textContent()) ?? "").match(/data: ([A-Z][a-z]+ [A-Z][a-z]+)/)?.[1];
  expect(subjectName).toBeTruthy();
  const count = await rows.count();
  for (let i = 0; i < count; i++) {
    const row = rows.nth(i);
    const text = (await row.textContent()) ?? "";
    await row.click();
    const disposition = text.includes(subjectName!) ? "TRUE_POSITIVE" : text.includes("crm-prod.customers") && !text.includes("CRM sync") ? "UNDETERMINED" : "BENIGN_POSITIVE";
    await page.getByLabel("Disposition", { exact: true }).selectOption(disposition);
    await page.getByLabel("Disposition justification").fill("Assessed against the correlated evidence");
    await page.getByRole("button", { name: "Save disposition" }).click();
    await expect(row).toContainText(disposition.replace(/_/g, " "));
  }

  // 9. investigate: open a case from the subject's alert and link evidence
  await exportRow.click();
  await page.getByRole("button", { name: "Open case from this alert" }).click();
  await expect(page.getByRole("heading", { name: /Case #1/ })).toBeVisible();
  const linkButtons = page.getByRole("button", { name: "Link as evidence" });
  while ((await linkButtons.count()) > 0) {
    const before = await linkButtons.count();
    await linkButtons.first().click();
    await expect(linkButtons).toHaveCount(before - 1);
  }
  await page.getByLabel("Evidence type").selectOption("GRANT");
  await page.getByLabel("Evidence item").selectOption("g-02");
  await page.getByRole("button", { name: "Link", exact: true }).click();
  await expect(page.getByText(/Grant g-02/)).toBeVisible();

  for (const [kind, text] of [["OBSERVATION", "Bulk download of the export followed by an outbound transfer attempt"],
    ["INFERENCE", "The subject attempted to move the export to a personal destination"],
    ["UNKNOWN", "Whether other copies were made off-platform is unknown"]] as const) {
    await page.getByLabel("Note kind").selectOption(kind);
    await page.getByLabel("Note text").fill(text);
    await expect(page.getByLabel("Note text")).toHaveValue(text);
    if (kind === "OBSERVATION") await page.locator("label.inline-check", { hasText: /^E\d+$/ }).first().locator("input").check();
    await expect(page.getByRole("button", { name: "Add note" })).toBeEnabled();
    await page.getByRole("button", { name: "Add note" }).click();
    await expect(page.locator("li", { hasText: text })).toBeVisible();
    await expect(page.getByLabel("Note text")).toHaveValue("");
  }

  // 10. scope & severity (the policy blocked the transfer, so nothing left the company)
  await page.getByRole("tab", { name: "Scope & severity" }).click();
  await page.getByLabel("Determination").selectOption("ATTEMPTED_EXFILTRATION_PREVENTED");
  await page.getByLabel("Exposure status").selectOption("ATTEMPT_PREVENTED");
  await page.getByLabel("Records potentially exposed").fill("0");
  await page.getByLabel("Severity").selectOption("HIGH");
  await page.locator("label.inline-check", { hasText: "customer_master_export_2026Q1.csv" }).locator("input").check();
  await page.locator("label.inline-check", { hasText: subjectName! }).locator("input").check();
  for (const rc of ["EXCESSIVE PERMISSION", "MISSING CLASSIFICATION", "MONITOR ONLY POLICY"]) {
    await page.locator("label.inline-check", { hasText: rc }).locator("input").check();
  }
  await page.getByRole("button", { name: "Save scope & severity" }).click();
  await expect(page.getByText("Scope and severity saved")).toBeVisible();

  // 11. apply authorised containment
  await page.getByRole("tab", { name: "Containment & remediation" }).click();
  const subjectOption = async () => {
    const opts = await page.getByLabel("Remediation target").locator("option").allTextContents();
    return opts.find((o) => o.startsWith(subjectName!))!;
  };
  for (const [action, target] of [["PRESERVE_EVIDENCE", null], ["DISABLE_ACCOUNT", null], ["ESCALATE", "PRIVACY_OFFICE"]] as const) {
    await page.getByLabel("Remediation action").selectOption(action);
    if (target) await page.getByLabel("Remediation target").selectOption(target);
    else await page.getByLabel("Remediation target").selectOption({ label: await subjectOption() });
    await page.getByLabel("Remediation justification").fill("Containment per incident procedure");
    await page.getByRole("button", { name: "Apply action" }).click();
    await expect(page.getByText(new RegExp(`${action} → (VERIFIED|RECORDED)`))).toBeVisible();
  }

  // fix the excessive permission
  await nav(page, "Classification Studio");
  await page.getByRole("tab", { name: "Ownership & access review" }).click();
  await page.getByLabel("Review note for g-02").fill("Support agents do not need bulk customer extracts");
  await page.getByRole("row", { name: /g-02/ }).getByRole("button", { name: "REVOKE" }).click();
  await expect(page.getByText("g-02: REVOKE")).toBeVisible();

  // 12. replay / retest
  await nav(page, "Simulation Workspace");
  await page.getByRole("button", { name: "Run control-validation replay" }).click();
  await expect(page.getByText(/Validation run 2: [1-9]\d* activities prevented/)).toBeVisible();

  // report sections
  await nav(page, "Incident Investigation");
  await page.getByRole("tab", { name: "Cases" }).click();
  await page.getByRole("row", { name: /#1/ }).click();
  await page.getByRole("tab", { name: "Report" }).click();
  await page.getByLabel("summary").fill("A support identity downloaded the full customer export and attempted to send it to a personal destination; DLP blocked it.");
  await page.getByLabel("root_cause_narrative").fill("Inherited folder access let agents read nightly exports; the export was unlabeled and DLP was monitor-only.");
  await page.getByLabel("residual_risk").fill("Other inherited share permissions are unreviewed; the subject's intent is not established.");
  await page.getByLabel("lessons_learned").fill("Label bulk extracts at creation, review export ACLs and move DLP from monitor to enforcement.");
  await page.getByRole("button", { name: "Save report sections" }).click();
  await expect(page.getByText("Report sections saved")).toBeVisible();

  // 13. submit the assessment
  await nav(page, "Assessment & Reports");
  await page.getByRole("button", { name: "Submit for assessment" }).click();
  await expect(page.getByText(/Guided practice result — attempt 1/)).toBeVisible();
  const score = Number((await page.locator(".stat").first().textContent())?.split("/")[0]);
  expect(score).toBeGreaterThanOrEqual(70);
  await expect(page.getByText("PASS", { exact: true }).first()).toBeVisible();

  // 14. open the generated report and confirm it reflects the executed actions
  await page.getByRole("row", { name: /Investigation case report/ }).getByRole("button", { name: "View" }).click();
  const report = page.getByTestId("report-body");
  await expect(report).toContainText("Execution mode: SIMULATED");
  await expect(report).toContainText("ATTEMPTED_EXFILTRATION_PREVENTED");
  await expect(report).toContainText("DISABLE_ACCOUNT");
  await expect(report).toContainText("PRESERVE_EVIDENCE");
  await expect(report).toContainText("Bulk download of the export followed by an outbound transfer attempt");
  await expect(report).toContainText("Control-validation replay");

  // reset and replay
  await nav(page, "Simulation Workspace");
  await page.getByRole("button", { name: "Reset" }).click();
  await expect(page.getByText(/Session #\d+ · attempt 2/)).toBeVisible();
  await expect(page.getByText("0% of tasks complete")).toBeVisible();
  await page.getByRole("button", { name: "Run business day" }).click();
  await expect(page.getByText(/Run 1: \d+ events, [1-9]\d* alerts/)).toBeVisible();
  await toastOrResult(page);
});

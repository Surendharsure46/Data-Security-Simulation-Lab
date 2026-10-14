/** Detector, synthetic content and scenario-definition validation tests. */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildContent, environmentTemplate } from "../src/content/company.js";
import { ibanValid, luhnValid, scanText } from "../src/domain/detection.js";
import { allDefinitions, publicView, SCENARIO_DIR, ScenarioDefinitionSchema } from "../src/domain/scenario-defs.js";

describe("detectors", () => {
  it("validates Luhn and IBAN checksums", () => {
    expect(luhnValid("4111111111111111")).toBe(true);
    expect(luhnValid("4111111111111112")).toBe(false);
    expect(ibanValid("DE89370400440532013000")).toBe(true);
    expect(ibanValid("DE89370400440532013001")).toBe(false);
  });

  it("masks card evidence and downgrades published test numbers", () => {
    const card = scanText("card_number\n4111111111111111\n").CREDIT_CARD;
    expect(card.confidence).toBe("LOW");
    expect(card.test_values).toBe(1);
    expect(card.evidence[0].masked_value.endsWith("1111")).toBe(true);
    expect(card.evidence[0].masked_value).not.toContain("4111111111");
  });

  it("ignores invalid numbers", () => {
    const res = scanText("ref 4111111111111112 ssn 000-12-3456 666-12-3456 912-12-3456");
    expect(res.CREDIT_CARD).toBeUndefined();
    expect(res.US_SSN).toBeUndefined();
  });

  it("raises confidence with keyword proximity", () => {
    expect(scanText("ssn: 123-45-6789").US_SSN.confidence).toBe("HIGH");
    expect(scanText("value 123-45-6789").US_SSN.confidence).toBe("MEDIUM");
  });

  it("requires a keyword for dates of birth and matches prefixed secret names", () => {
    expect(scanText("shipped 2026-03-09").DATE_OF_BIRTH).toBeUndefined();
    expect(scanText("date_of_birth\n1984-05-02").DATE_OF_BIRTH).toBeDefined();
    const sec = scanText("CRM_CLIENT_SECRET=krsim-SYNTHETIC-9f8e7d6c5b4a3921").SECRET_CREDENTIAL;
    expect(sec.evidence[0].masked_value).toBe("CRM_CLIENT_SECRET=<redacted>");
  });
});

describe("synthetic content", () => {
  it("is detectable and deterministic", () => {
    const c1 = buildContent();
    expect(buildContent()).toEqual(c1);
    const exportScan = scanText(c1["ast-cust-export-q1"]);
    for (const d of ["CREDIT_CARD", "EMAIL_ADDRESS", "CUSTOMER_ACCOUNT", "DATE_OF_BIRTH", "PHONE_NUMBER"]) expect(exportScan[d], d).toBeDefined();
    expect(exportScan.CREDIT_CARD.confidence).toBe("HIGH");
    expect(scanText(c1["ast-payroll-mar"]).IBAN).toBeDefined();
    expect(scanText(c1["ast-hr-records"]).US_SSN).toBeDefined();
    expect(scanText(c1["ast-api-config"]).SECRET_CREDENTIAL).toBeDefined();
    const masked = scanText(c1["ast-cust-sample-masked"]);
    expect(masked.CREDIT_CARD).toBeUndefined();
    expect(masked.EMAIL_ADDRESS).toBeUndefined();
  });

  it("uses reserved example domains only", () => {
    const blob = JSON.stringify(environmentTemplate());
    const domains = new Set([...blob.matchAll(/@([a-z0-9.-]+\.[a-z]+)/g)].map((m) => m[1]));
    for (const d of domains) expect(d.endsWith(".example") || ["example.com", "example.net", "example.org"].includes(d), d).toBe(true);
  });
});

describe("scenario definitions", () => {
  const raw = JSON.parse(readFileSync(join(SCENARIO_DIR, "customer-data-export.json"), "utf8"));

  it("all validate", () => {
    expect(allDefinitions().has("customer-data-export")).toBe(true);
  });

  it("public view never contains hidden answers", () => {
    const view = JSON.stringify(publicView(allDefinitions().get("customer-data-export")!));
    for (const secret of ["ground_truth", "u-jokafor", "u-rsilva", '"timeline":', "culprit", "TRUE_POSITIVE", "g-02", "S08"]) {
      expect(view, secret).not.toContain(secret);
    }
  });

  it("rejects invalid definitions", () => {
    const bad = structuredClone(raw);
    bad.timeline[0].actor = "u-nobody";
    expect(ScenarioDefinitionSchema.safeParse(bad).success).toBe(false);
    const bad2 = structuredClone(raw);
    bad2.rubric.criteria[0].check = "os.system";
    expect(ScenarioDefinitionSchema.safeParse(bad2).success).toBe(false);
    const bad3 = structuredClone(raw);
    bad3.rubric.categories.technical.weight = 50;
    expect(ScenarioDefinitionSchema.safeParse(bad3).success).toBe(false);
  });
});

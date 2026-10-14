/**
 * Sensitive-data detectors. Each detector combines a regular expression with an optional validator (Luhn,
 * IBAN mod-97, SSN area rules) and keyword proximity to assign a confidence level. Evidence returned to clients is
 * always masked.
 */
export const CONFIDENCE_ORDER: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2 };

// Published payment-network test numbers. Matches are reported but downgraded to LOW.
export const KNOWN_TEST_PANS = new Set([
  "4111111111111111", "4242424242424242", "4012888888881881", "5555555555554444", "5105105105105100", "378282246310005", "6011111111111117",
]);

export function luhnValid(digits: string): boolean {
  let total = 0;
  [...digits].reverse().forEach((ch, i) => {
    let d = Number(ch);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  });
  return total % 10 === 0;
}

export function ibanValid(value: string): boolean {
  const v = value.replace(/ /g, "").toUpperCase();
  if (v.length < 15 || v.length > 34) return false;
  const rearranged = v.slice(4) + v.slice(0, 4);
  const numeric = [...rearranged].map((c) => parseInt(c, 36).toString()).join("");
  if (!/^\d+$/.test(numeric)) return false;
  return BigInt(numeric) % 97n === 1n;
}

const isAlnum = (c: string) => /[A-Za-z0-9]/.test(c);

function maskKeepLast(value: string, keep = 4): string {
  let remaining = [...value].filter(isAlnum).length;
  return [...value].map((c) => {
    if (!isAlnum(c)) return c;
    const out = remaining <= keep ? c : "*";
    remaining -= 1;
    return out;
  }).join("");
}

function maskEmail(value: string): string {
  const at = value.indexOf("@");
  return `${value.slice(0, 1)}***@${value.slice(at + 1)}`;
}

const digits = (s: string) => s.replace(/\D/g, "");

interface Detector {
  key: string;
  name: string;
  description: string;
  pattern: RegExp;
  baseConfidence: string;
  keywords: string[];
  validator?: (v: string) => boolean;
  masker: (v: string) => string;
  requiresKeyword: boolean;
}

const det = (d: Partial<Detector> & Pick<Detector, "key" | "name" | "description" | "pattern" | "baseConfidence">): Detector => ({
  keywords: [], masker: maskKeepLast, requiresKeyword: false, ...d,
});

export const DETECTORS: Record<string, Detector> = Object.fromEntries([
  det({
    key: "CREDIT_CARD", name: "Payment card number (PAN)", description: "13-19 digit number passing the Luhn checksum.",
    // Contiguous digits or consistently separated groups (4-4-4-4[-n] or Amex 4-6-5); mixed separators are not cards.
    pattern: /\b(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?|\d{4}([ -])\d{6}\2\d{5})\b/g,
    baseConfidence: "MEDIUM", keywords: ["card", "pan", "cc_number", "credit"],
    validator: (v) => { const d = digits(v); return d.length >= 13 && d.length <= 19 && luhnValid(d); },
  }),
  det({
    key: "US_SSN", name: "US Social Security number format",
    description: "ddd-dd-dddd excluding invalid areas (000, 666, 9xx), group 00 and serial 0000.",
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, baseConfidence: "MEDIUM", keywords: ["ssn", "social security", "national_id"],
  }),
  det({
    key: "IBAN", name: "International bank account number", description: "IBAN structure validated with ISO 7064 mod-97.",
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, baseConfidence: "HIGH", keywords: ["iban", "bank"], validator: ibanValid,
  }),
  det({
    key: "EMAIL_ADDRESS", name: "Email address", description: "RFC-like email address.",
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, baseConfidence: "MEDIUM", keywords: ["email", "e-mail"], masker: maskEmail,
  }),
  det({
    key: "PHONE_NUMBER", name: "Phone number", description: "North American style phone number.",
    pattern: /(?<!\d)(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)/g, baseConfidence: "MEDIUM", keywords: ["phone", "mobile", "tel"],
  }),
  det({
    key: "DATE_OF_BIRTH", name: "Date of birth", description: "Date value appearing near a birth-date keyword (keyword required).",
    pattern: /\b(?:19|20)\d{2}-\d{2}-\d{2}\b/g, baseConfidence: "MEDIUM", keywords: ["dob", "date_of_birth", "birth"], requiresKeyword: true,
    masker: (v) => v.slice(0, 2) + "**-**-**",
  }),
  det({
    key: "CUSTOMER_ACCOUNT", name: "Kestrel Ridge customer account number", description: "Organisation-specific identifier KRC-########.",
    pattern: /\bKRC-\d{8}\b/g, baseConfidence: "HIGH",
  }),
  det({
    key: "EMPLOYEE_ID", name: "Kestrel Ridge employee identifier", description: "Organisation-specific identifier KR-E-######.",
    pattern: /\bKR-E-\d{6}\b/g, baseConfidence: "MEDIUM",
  }),
  det({
    key: "SECRET_CREDENTIAL", name: "Credential or secret assignment", description: "key/secret/password assigned a value of 12+ characters.",
    // [\w-]* lets prefixed names such as CRM_CLIENT_SECRET match (no word boundary inside identifiers).
    pattern: /\b[\w-]*(?:api[_-]?key|secret|password|passwd|token)\b\s*[=:]\s*\S{12,}/gi, baseConfidence: "HIGH",
    masker: (v) => v.split("=")[0].split(":")[0] + "=<redacted>",
  }),
  det({
    key: "CONFIDENTIAL_MARKER", name: "Confidentiality marking", description: "Document marked confidential, privileged or restricted.",
    pattern: /\b(?:strictly confidential|confidential|attorney[- ]client privileged)\b/gi, baseConfidence: "MEDIUM", masker: (v) => v,
  }),
].map((d) => [d.key, d]));

export interface DetectorResult {
  detector: string;
  match_count: number;
  confidence: string;
  evidence: { line: number; masked_value: string; confidence: string; note: string }[];
  test_values: number;
}

function keywordNear(text: string, start: number, keywords: string[], window = 80): boolean {
  if (!keywords.length) return false;
  const region = text.slice(Math.max(0, start - window), start).toLowerCase();
  // Structured data: the first non-comment line is the header, so column names count as context.
  const header = (text.split("\n").find((ln) => ln.trim() && !ln.trimStart().startsWith("#") && !ln.trimStart().startsWith("--")) ?? "").toLowerCase();
  return keywords.some((k) => region.includes(k) || header.includes(k));
}

/** Scan text with all (or the enabled) detectors. Returns only detectors with matches. */
export function scanText(text: string, enabled?: Set<string>): Record<string, DetectorResult> {
  const results: Record<string, DetectorResult> = {};
  for (const [key, d] of Object.entries(DETECTORS)) {
    if (enabled && !enabled.has(key)) continue;
    const res: DetectorResult = { detector: key, match_count: 0, confidence: "LOW", evidence: [], test_values: 0 };
    for (const m of text.matchAll(d.pattern)) {
      const value = m[0].trim();
      if (d.validator && !d.validator(value)) continue;
      const near = keywordNear(text, m.index!, d.keywords);
      if (d.requiresKeyword && !near) continue;
      let conf = d.baseConfidence;
      let note = "";
      if (near && conf === "MEDIUM") conf = "HIGH";
      if (key === "CREDIT_CARD" && KNOWN_TEST_PANS.has(digits(value))) {
        conf = "LOW";
        note = "Known published test card number";
        res.test_values += 1;
      }
      res.match_count += 1;
      if (res.match_count === 1 || CONFIDENCE_ORDER[conf] > CONFIDENCE_ORDER[res.confidence]) res.confidence = conf;
      if (res.evidence.length < 3) {
        const line = text.slice(0, m.index!).split("\n").length;
        res.evidence.push({ line, masked_value: d.masker(value), confidence: conf, note });
      }
    }
    if (res.match_count) results[key] = res;
  }
  return results;
}

export function maxConfidence(results: Record<string, DetectorResult>): string | null {
  let best: string | null = null;
  for (const r of Object.values(results)) if (best === null || CONFIDENCE_ORDER[r.confidence] > CONFIDENCE_ORDER[best]) best = r.confidence;
  return best;
}

export function detectorCatalog() {
  return Object.values(DETECTORS).map((d) => ({
    key: d.key, name: d.name, description: d.description, base_confidence: d.baseConfidence, keywords: d.keywords,
    validator: d.validator !== undefined, requires_keyword: d.requiresKeyword,
  }));
}

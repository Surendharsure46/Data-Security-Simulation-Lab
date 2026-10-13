"""Sensitive-data detectors.

Each detector combines a regular expression with an optional validator (Luhn, IBAN
mod-97, SSN area rules) and keyword proximity to assign a confidence level.
Evidence returned to clients is always masked.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

# Published payment-network test numbers. Matches are reported but downgraded to LOW.
KNOWN_TEST_PANS = {
    "4111111111111111",
    "4242424242424242",
    "4012888888881881",
    "5555555555554444",
    "5105105105105100",
    "378282246310005",
    "6011111111111117",
}


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(value: str) -> bool:
    v = value.replace(" ", "").upper()
    if len(v) < 15 or len(v) > 34:
        return False
    rearranged = v[4:] + v[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def _mask_keep_last(value: str, keep: int = 4) -> str:
    out = []
    remaining = sum(c.isalnum() for c in value)
    for c in value:
        if c.isalnum():
            out.append(c if remaining <= keep else "*")
            remaining -= 1
        else:
            out.append(c)
    return "".join(out)


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:1]}***@{domain}"


@dataclass(frozen=True)
class Detector:
    key: str
    name: str
    description: str
    pattern: re.Pattern[str]
    base_confidence: str
    keywords: tuple[str, ...] = ()
    validator: Callable[[str], bool] | None = None
    masker: Callable[[str], str] = _mask_keep_last
    requires_keyword: bool = False


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


DETECTORS: dict[str, Detector] = {
    d.key: d
    for d in [
        Detector(
            "CREDIT_CARD",
            "Payment card number (PAN)",
            "13-19 digit number passing the Luhn checksum.",
            # Contiguous digits or consistently separated groups (4-4-4-4[-n] or Amex 4-6-5); mixed separators are not cards.
            re.compile(r"\b(?:\d{13,19}|\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?|\d{4}([ -])\d{6}\2\d{5})\b"),
            "MEDIUM",
            keywords=("card", "pan", "cc_number", "credit"),
            validator=lambda v: 13 <= len(_digits(v)) <= 19 and luhn_valid(_digits(v)),
        ),
        Detector(
            "US_SSN",
            "US Social Security number format",
            "ddd-dd-dddd excluding invalid areas (000, 666, 9xx), group 00 and serial 0000.",
            re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
            "MEDIUM",
            keywords=("ssn", "social security", "national_id"),
        ),
        Detector(
            "IBAN",
            "International bank account number",
            "IBAN structure validated with ISO 7064 mod-97.",
            re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
            "HIGH",
            keywords=("iban", "bank"),
            validator=iban_valid,
        ),
        Detector(
            "EMAIL_ADDRESS",
            "Email address",
            "RFC-like email address.",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "MEDIUM",
            keywords=("email", "e-mail"),
            masker=_mask_email,
        ),
        Detector(
            "PHONE_NUMBER",
            "Phone number",
            "North American style phone number.",
            re.compile(r"(?<!\d)(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"),
            "MEDIUM",
            keywords=("phone", "mobile", "tel"),
        ),
        Detector(
            "DATE_OF_BIRTH",
            "Date of birth",
            "Date value appearing near a birth-date keyword (keyword required).",
            re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b"),
            "MEDIUM",
            keywords=("dob", "date_of_birth", "birth"),
            requires_keyword=True,
            masker=lambda v: v[:2] + "**-**-**",
        ),
        Detector(
            "CUSTOMER_ACCOUNT",
            "Kestrel Ridge customer account number",
            "Organisation-specific identifier KRC-########.",
            re.compile(r"\bKRC-\d{8}\b"),
            "HIGH",
        ),
        Detector(
            "EMPLOYEE_ID",
            "Kestrel Ridge employee identifier",
            "Organisation-specific identifier KR-E-######.",
            re.compile(r"\bKR-E-\d{6}\b"),
            "MEDIUM",
        ),
        Detector(
            "SECRET_CREDENTIAL",
            "Credential or secret assignment",
            "key/secret/password assigned a value of 12+ characters.",
            # [\w-]* lets prefixed names such as CRM_CLIENT_SECRET match (no word boundary inside identifiers).
            re.compile(r"(?i)\b[\w-]*(?:api[_-]?key|secret|password|passwd|token)\b\s*[=:]\s*\S{12,}"),
            "HIGH",
            masker=lambda v: v.split("=")[0].split(":")[0] + "=<redacted>",
        ),
        Detector(
            "CONFIDENTIAL_MARKER",
            "Confidentiality marking",
            "Document marked confidential, privileged or restricted.",
            re.compile(r"(?i)\b(?:strictly confidential|confidential|attorney[- ]client privileged)\b"),
            "MEDIUM",
            masker=lambda v: v,
        ),
    ]
}


@dataclass
class DetectorResult:
    detector: str
    match_count: int = 0
    confidence: str = "LOW"
    evidence: list[dict] = field(default_factory=list)
    test_values: int = 0


def _keyword_near(text: str, start: int, keywords: tuple[str, ...], window: int = 80) -> bool:
    if not keywords:
        return False
    lo = max(0, start - window)
    region = text[lo:start].lower()
    # Structured data: the first non-comment line is the header, so column names count as context.
    header = next((ln for ln in text.split("\n") if ln.strip() and not ln.lstrip().startswith(("#", "--"))), "").lower()
    return any(k in region or k in header for k in keywords)


def scan_text(text: str, enabled: set[str] | None = None) -> dict[str, DetectorResult]:
    """Scan text with all (or the enabled) detectors. Returns only detectors with matches."""
    results: dict[str, DetectorResult] = {}
    for key, det in DETECTORS.items():
        if enabled is not None and key not in enabled:
            continue
        res = DetectorResult(detector=key)
        for m in det.pattern.finditer(text):
            value = m.group(0).strip()
            if det.validator and not det.validator(value):
                continue
            near = _keyword_near(text, m.start(), det.keywords)
            if det.requires_keyword and not near:
                continue
            conf = det.base_confidence
            note = ""
            if near and conf == "MEDIUM":
                conf = "HIGH"
            if key == "CREDIT_CARD" and _digits(value) in KNOWN_TEST_PANS:
                conf = "LOW"
                note = "Known published test card number"
                res.test_values += 1
            res.match_count += 1
            if res.match_count == 1 or CONFIDENCE_ORDER[conf] > CONFIDENCE_ORDER[res.confidence]:
                res.confidence = conf
            if len(res.evidence) < 3:
                line_no = text.count("\n", 0, m.start()) + 1
                res.evidence.append(
                    {"line": line_no, "masked_value": det.masker(value), "confidence": conf, "note": note}
                )
        if res.match_count:
            results[key] = res
    return results


def detector_catalog() -> list[dict]:
    return [
        {
            "key": d.key,
            "name": d.name,
            "description": d.description,
            "base_confidence": d.base_confidence,
            "keywords": list(d.keywords),
            "validator": d.validator is not None,
            "requires_keyword": d.requires_keyword,
        }
        for d in DETECTORS.values()
    ]

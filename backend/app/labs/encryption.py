"""Encryption Lab.

REAL_LAB exercises use the ``cryptography`` library on disposable synthetic files:
AES-256-GCM with an scrypt-derived key, SHA-256 / HMAC-SHA256, and envelope
encryption with RFC 3394 AES key wrap. No custom cryptography is implemented.
The TLS metadata exercise and configuration review are SIMULATED.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap, aes_key_wrap

from ..services.common import DomainError

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
MAGIC = b"TRLAB1\n"

SAMPLE_PLAINTEXT = (
    "customer_id,full_name,email,card_last4\n"
    "KRC-10293847,Avery Castellano,avery.castellano@example.com,4821\n"
    "KRC-55102938,Rowan Eastwood,rowan.eastwood@example.net,1177\n"
    "KRC-77319201,Quinn Hollister,quinn.hollister@example.org,9034\n"
    "# synthetic training data - Threatready encryption lab\n"
).encode()

HASH_FILES = {
    "payroll_batch_A.csv": "employee_id,net_pay\nKR-E-100231,4210.55\nKR-E-100232,3988.10\nKR-E-100233,5120.00\n",
    "payroll_batch_B.csv": "employee_id,net_pay\nKR-E-100231,4210.55\nKR-E-100232,3988.10\nKR-E-100233,5120.00\n",
    "payroll_batch_C.csv": "employee_id,net_pay\nKR-E-100231,4210.55\nKR-E-100232,8988.10\nKR-E-100233,5120.00\n",
}
# The manifest published by Finance before transfer (hash of the original batch).
MANIFEST = {"original_batch_sha256": hashlib.sha256(HASH_FILES["payroll_batch_A.csv"].encode()).hexdigest()}
TAMPERED_FILE = "payroll_batch_C.csv"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- hashing


def hash_file(name: str) -> dict[str, Any]:
    if name not in HASH_FILES:
        raise DomainError("Unknown lab file", 404)
    data = HASH_FILES[name].encode()
    return {"file": name, "sha256": sha256_hex(data), "bytes": len(data)}


def hmac_demo(message: str, key_label: str) -> dict[str, Any]:
    key = hashlib.sha256(f"threatready-lab-hmac-{key_label}".encode()).digest()
    return {"hmac_sha256": hmac.new(key, message.encode(), hashlib.sha256).hexdigest(),
            "sha256": sha256_hex(message.encode()),
            "note": "A plain hash can be recomputed by anyone; an HMAC requires the shared key, so it also proves origin."}


# --------------------------------------------------------------------------- file encryption


def _derive(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode())


def encrypt_sample(d: Path, passphrase: str) -> dict[str, Any]:
    if len(passphrase) < 12:
        raise DomainError("Use a passphrase of at least 12 characters")
    (d / "customer_sample.csv").write_bytes(SAMPLE_PLAINTEXT)
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {"alg": "AES-256-GCM", "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
              "salt": salt.hex(), "nonce": nonce.hex()}
    hdr = json.dumps(header, sort_keys=True).encode()
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, SAMPLE_PLAINTEXT, hdr)  # header authenticated as AAD
    blob = MAGIC + len(hdr).to_bytes(2, "big") + hdr + ct
    (d / "customer_sample.csv.enc").write_bytes(blob)
    return {"header": header, "ciphertext_bytes": len(ct), "ciphertext_prefix_hex": ct[:24].hex(),
            "file_sha256": sha256_hex(blob), "plaintext_sha256": sha256_hex(SAMPLE_PLAINTEXT),
            "plaintext_written": "customer_sample.csv", "encrypted_written": "customer_sample.csv.enc",
            "tag_bytes": 16, "provenance": "REAL_LAB"}


def _read_blob(d: Path) -> tuple[dict[str, Any], bytes, bytes]:
    p = d / "customer_sample.csv.enc"
    if not p.exists():
        raise DomainError("Encrypt the sample file first", 409)
    blob = p.read_bytes()
    if not blob.startswith(MAGIC):
        raise DomainError("Unrecognised file format", 422)
    n = int.from_bytes(blob[len(MAGIC):len(MAGIC) + 2], "big")
    hdr = blob[len(MAGIC) + 2:len(MAGIC) + 2 + n]
    return json.loads(hdr), hdr, blob[len(MAGIC) + 2 + n:]


def decrypt_sample(d: Path, passphrase: str) -> dict[str, Any]:
    header, hdr, ct = _read_blob(d)
    try:
        pt = AESGCM(_derive(passphrase, bytes.fromhex(header["salt"]))).decrypt(bytes.fromhex(header["nonce"]), ct, hdr)
    except InvalidTag:
        return {"success": False, "error": "InvalidTag: authentication failed. Wrong key or modified ciphertext; no plaintext was released.",
                "provenance": "REAL_LAB"}
    return {"success": True, "plaintext_sha256": sha256_hex(pt), "matches_original": pt == SAMPLE_PLAINTEXT,
            "preview": pt.decode()[:160], "provenance": "REAL_LAB"}


def tamper_sample(d: Path) -> dict[str, Any]:
    p = d / "customer_sample.csv.enc"
    if not p.exists():
        raise DomainError("Encrypt the sample file first", 409)
    blob = bytearray(p.read_bytes())
    idx = len(blob) - 20  # inside the ciphertext body, before the tag
    blob[idx] ^= 0x01
    p.write_bytes(bytes(blob))
    return {"modified_byte_offset": idx, "file_sha256": sha256_hex(bytes(blob)), "provenance": "REAL_LAB"}


# --------------------------------------------------------------------------- envelope encryption


ENVELOPE_DATA = b"payroll backup 2026-03 (synthetic)\n" + b"KR-E-100231,DE89370400440532013000,4210.55\n" * 20


def _keyring_path(d: Path) -> Path:
    return d / "lab_keyring.json"


def envelope_init(d: Path) -> dict[str, Any]:
    kek = AESGCM.generate_key(bit_length=256)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, ENVELOPE_DATA, b"backup_payroll.dat")
    (d / "backup_payroll.dat.enc").write_bytes(nonce + ct)
    wrapped = aes_key_wrap(kek, dek)
    ring = {"active": "kek-v1", "keys": {"kek-v1": {"material": kek.hex(), "status": "ACTIVE"}},
            "wrapped_dek": wrapped.hex(), "wrapped_by": "kek-v1"}
    _keyring_path(d).write_text(json.dumps(ring))
    return {"kek_id": "kek-v1", "wrapped_dek_hex": wrapped.hex(), "data_ciphertext_sha256": sha256_hex(nonce + ct),
            "note": "Lab keyring stored on disk for the exercise only. Production KEKs live in a KMS or HSM and never leave it.",
            "provenance": "REAL_LAB"}


def _ring(d: Path) -> dict[str, Any]:
    p = _keyring_path(d)
    if not p.exists():
        raise DomainError("Initialise envelope encryption first", 409)
    return json.loads(p.read_text())


def envelope_rotate(d: Path) -> dict[str, Any]:
    ring = _ring(d)
    old_id = ring["active"]
    old = bytes.fromhex(ring["keys"][old_id]["material"])
    dek = aes_key_unwrap(old, bytes.fromhex(ring["wrapped_dek"]))
    new_id = f"kek-v{len(ring['keys']) + 1}"
    new = AESGCM.generate_key(bit_length=256)
    ring["keys"][old_id]["status"] = "RETIRED"
    ring["keys"][new_id] = {"material": new.hex(), "status": "ACTIVE"}
    ring["active"] = new_id
    ring["wrapped_dek"] = aes_key_wrap(new, dek).hex()
    ring["wrapped_by"] = new_id
    _keyring_path(d).write_text(json.dumps(ring))
    data = (d / "backup_payroll.dat.enc").read_bytes()
    return {"retired": old_id, "active": new_id, "wrapped_dek_hex": ring["wrapped_dek"],
            "data_ciphertext_sha256": sha256_hex(data),
            "note": "Only the wrapped DEK changed; the bulk data ciphertext is byte-for-byte identical.", "provenance": "REAL_LAB"}


def envelope_decrypt(d: Path, kek_id: str | None = None) -> dict[str, Any]:
    ring = _ring(d)
    kid = kek_id or ring["active"]
    if kid not in ring["keys"]:
        raise DomainError("Unknown key id", 404)
    try:
        dek = aes_key_unwrap(bytes.fromhex(ring["keys"][kid]["material"]), bytes.fromhex(ring["wrapped_dek"]))
    except InvalidUnwrap:
        return {"success": False, "kek_id": kid, "error": f"InvalidUnwrap: {kid} cannot unwrap the current DEK (it was re-wrapped).",
                "provenance": "REAL_LAB"}
    blob = (d / "backup_payroll.dat.enc").read_bytes()
    pt = AESGCM(dek).decrypt(blob[:12], blob[12:], b"backup_payroll.dat")
    return {"success": True, "kek_id": kid, "plaintext_sha256": sha256_hex(pt), "matches_original": pt == ENVELOPE_DATA,
            "data_ciphertext_sha256": sha256_hex(blob), "provenance": "REAL_LAB"}


# --------------------------------------------------------------------------- TLS metadata (simulated)

TLS_CAPTURE = {
    "provenance": "SIMULATED",
    "description": "Summary of a synthetic TLS 1.3 session from a lab laptop to portal.kestrelridge.example. Not a real capture.",
    "records": [
        {"t": "0.000", "dir": "client→server", "type": "TCP SYN", "detail": "10.20.44.18:51544 → 203.0.113.40:443"},
        {"t": "0.031", "dir": "client→server", "type": "ClientHello", "detail": "SNI=portal.kestrelridge.example; supported_versions=TLS1.3,TLS1.2; ALPN=h2"},
        {"t": "0.064", "dir": "server→client", "type": "ServerHello", "detail": "selected TLS1.3; cipher TLS_AES_128_GCM_SHA256; key_share x25519"},
        {"t": "0.065", "dir": "server→client", "type": "Encrypted handshake", "detail": "EncryptedExtensions, Certificate, CertificateVerify, Finished (encrypted, 3,412 bytes)"},
        {"t": "0.120", "dir": "client→server", "type": "Application data", "detail": "encrypted record, 1,108 bytes"},
        {"t": "0.233", "dir": "server→client", "type": "Application data", "detail": "encrypted records, 48,880 bytes total"},
    ],
}
TLS_ITEMS = {
    "destination_ip": True, "sni_hostname": True, "tls_version_and_cipher": True, "packet_sizes_and_timing": True,
    "url_path": False, "http_cookies": False, "form_field_values": False, "server_certificate_tls13": False,
}
TLS_LABELS = {
    "destination_ip": "Destination IP address and port", "sni_hostname": "Server name (SNI)",
    "tls_version_and_cipher": "Negotiated TLS version and cipher suite", "packet_sizes_and_timing": "Packet sizes and timing",
    "url_path": "Requested URL path", "http_cookies": "HTTP cookies", "form_field_values": "Submitted form field values",
    "server_certificate_tls13": "Server certificate (TLS 1.3)",
}


def grade_tls(visible: list[str]) -> dict[str, Any]:
    unknown = set(visible) - set(TLS_ITEMS)
    if unknown:
        raise DomainError(f"Unknown items: {sorted(unknown)}")
    chosen = set(visible)
    correct = {k: (k in chosen) == v for k, v in TLS_ITEMS.items()}
    return {"passed": all(correct.values()), "correct_count": sum(correct.values()), "total": len(TLS_ITEMS),
            "per_item": correct}


# --------------------------------------------------------------------------- configuration review (simulated)

WEAK_CONFIG = {
    "service": "kr-backup-service (simulated)",
    "tls_min_version": "TLS1.0",
    "cipher_suites": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
    "verify_server_certificate": False,
    "at_rest_algorithm": "AES-128-ECB",
    "key_location": "same_volume",
    "key_rotation_days": 0,
    "backup_encryption": False,
    "secret_storage": "plaintext_config",
}
CONFIG_OPTIONS = {
    "tls_min_version": ["TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"],
    "cipher_suites": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
    "at_rest_algorithm": ["AES-128-ECB", "AES-256-CBC", "AES-256-GCM", "ChaCha20-Poly1305", "DES"],
    "key_location": ["same_volume", "config_file", "kms", "hsm"],
    "secret_storage": ["plaintext_config", "environment_variable", "vault", "kms"],
}
AEAD_SUITES = {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
               "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}


def validate_config(cfg: dict[str, Any]) -> list[dict[str, str]]:
    """Deterministic validator; each rule maps to a documented weakness."""
    f: list[dict[str, str]] = []
    for k, opts in CONFIG_OPTIONS.items():
        v = cfg.get(k)
        vals = v if isinstance(v, list) else [v]
        if any(x not in opts for x in vals):
            raise DomainError(f"Invalid value for {k}")
    if cfg["tls_min_version"] in ("TLS1.0", "TLS1.1"):
        f.append({"id": "ENC-01", "severity": "HIGH", "finding": "Legacy TLS versions enabled", "fix": "Set minimum version to TLS1.2 or TLS1.3."})
    weak = [s for s in cfg["cipher_suites"] if s not in AEAD_SUITES]
    if weak:
        f.append({"id": "ENC-02", "severity": "HIGH", "finding": f"Non-AEAD or legacy cipher suites: {', '.join(weak)}", "fix": "Allow only AEAD suites (GCM / ChaCha20-Poly1305)."})
    if not cfg["cipher_suites"]:
        f.append({"id": "ENC-02b", "severity": "HIGH", "finding": "No cipher suites configured", "fix": "Enable at least one AEAD suite."})
    if not cfg["verify_server_certificate"]:
        f.append({"id": "ENC-03", "severity": "CRITICAL", "finding": "Server certificate validation disabled (interception possible)", "fix": "Enable certificate validation."})
    if cfg["at_rest_algorithm"] not in ("AES-256-GCM", "ChaCha20-Poly1305"):
        f.append({"id": "ENC-04", "severity": "HIGH", "finding": f"At-rest algorithm {cfg['at_rest_algorithm']} is unauthenticated or weak", "fix": "Use AES-256-GCM or ChaCha20-Poly1305."})
    if cfg["key_location"] not in ("kms", "hsm"):
        f.append({"id": "ENC-05", "severity": "HIGH", "finding": "Encryption key stored alongside the data or in configuration", "fix": "Store keys in a KMS or HSM."})
    days = cfg["key_rotation_days"]
    if not isinstance(days, int) or days <= 0 or days > 365:
        f.append({"id": "ENC-06", "severity": "MEDIUM", "finding": "Key rotation disabled or longer than 365 days", "fix": "Rotate keys at least annually (1-365 days)."})
    if not cfg["backup_encryption"]:
        f.append({"id": "ENC-07", "severity": "HIGH", "finding": "Backups are not encrypted", "fix": "Enable backup encryption."})
    if cfg["secret_storage"] not in ("vault", "kms"):
        f.append({"id": "ENC-08", "severity": "HIGH", "finding": "Database password stored outside a secrets manager", "fix": "Use a vault or KMS-backed secret store."})
    return f

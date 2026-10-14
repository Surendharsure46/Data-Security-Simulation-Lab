/** Lab catalogue: which exercises each hands-on lab records. Used by the lab status endpoint and career content checks. */
export const LAB_EXERCISES: Record<string, { mode: string; exercises: string[] }> = {
  encryption: { mode: "REAL_LAB (TLS and config review: SIMULATED)", exercises: ["hashing", "file_roundtrip", "envelope_rotation", "tls_metadata", "config_review"] },
  database: { mode: "REAL_LAB", exercises: ["least_privilege", "injection", "masking", "audit", "backup_restore"] },
  cloud: { mode: "SIMULATED", exercises: ["assess", "remediate"] },
  privacy: { mode: "SIMULATED", exercises: ["minimization", "retention", "report"] },
  ai: { mode: "SIMULATED", exercises: ["prompt_gateway", "rag_acl", "retention"] },
};

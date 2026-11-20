"""Central settings and thresholds. Change values here, not inside the modules."""

REGION = "us-east-1"
TABLE_NAME = "PasswordAuditRecords"          # (mock) DynamoDB table for hash records
PEPPER_SECRET_NAME = "cpsa/app-pepper"       # (mock) Secrets Manager secret holding the pepper

# --- Password rules (NIST SP 800-63B / CIS AWS Foundations) ---
MIN_LENGTH_NIST = 8            # NIST 800-63B 5.1.1.1: absolute minimum for user-chosen secrets
MIN_LENGTH_RECOMMENDED = 14    # CIS AWS Foundations: recommended IAM minimum
REUSE_PREVENTION_MIN = 24      # CIS AWS Foundations: remember last 24 passwords
MAX_ANALYZED_CHARS = 128       # zxcvbn gets slow on huge inputs; only the first N chars are pattern-analysed

# --- IAM credential hygiene ---
KEY_MAX_AGE_DAYS = 90          # access keys older than this should be rotated
UNUSED_CREDENTIAL_DAYS = 45    # credentials idle this long should be disabled
FORCED_EXPIRY_DAYS = 90        # NIST discourages forced periodic rotation at or below this

# --- Hashing cost (tests lower these so they run fast) ---
BCRYPT_ROUNDS = 12
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536     # KiB
ARGON2_PARALLELISM = 4

# --- Reporting ---
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}

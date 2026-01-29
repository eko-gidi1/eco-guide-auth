-- UUID generation extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (minimal PII, focus on auth-related metadata)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    consented_at TIMESTAMP WITH TIME ZONE,
    status SMALLINT DEFAULT 0, -- 0=pre-consent, 1=active, 2=suspended
    metadata JSONB DEFAULT '{}' -- Arbitrary, non-sensitive profile data (e.g., preferred_lang)
);

-- user_devices table
CREATE TABLE user_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL, -- Client-provided stable device ID hash
    device_fingerprint_hash TEXT NOT NULL, -- Hash of user-agent + other client-side non-PII data
    attestation_status SMALLINT DEFAULT 0, -- 0=none, 1=basic, 2=strong
    local_pin_biometric BOOLEAN DEFAULT false,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    UNIQUE(user_id, device_id)
);

-- refresh_tokens (stores only token_hash + metadata)
CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY, -- HMAC_SHA256(raw_token)
    jti UUID NOT NULL DEFAULT uuid_generate_v4(), -- JWT ID, unique identifier for the token
    family_id UUID NOT NULL, -- Grouping for token rotation chain
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID, -- References user_devices.id (optional, can be text hash)
    issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    prev_token_hash TEXT, -- Hash of the previous token in the rotation chain (for reuse detection)
    is_revoked BOOLEAN DEFAULT FALSE,
    created_by TEXT, -- Client application id (e.g., 'web', 'android', 'ios')
    metadata JSONB DEFAULT '{}' -- Any other relevant token-specific, non-sensitive data
);
CREATE INDEX idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);

-- otp_logs (Audit only, NO plaintext OTP) - if DB persistence is required, otherwise Redis cache is preferred
CREATE TABLE otp_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    temp_user_id TEXT, -- Temporary ID during OTP flow
    otp_hmac TEXT, -- HMAC of the OTP (short-TTL in Redis; if persistent, needs strong KDF)
    channel TEXT, -- sms, email, push
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    consumed BOOLEAN DEFAULT FALSE,
    consumed_at TIMESTAMP WITH TIME ZONE
);

-- consent_logs (Anonymous audit trail for consent actions)
CREATE TABLE consent_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID, -- NULL if pre-user creation, linked after consent
    action TEXT NOT NULL, -- 'agree', 'decline'
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
    audit_id UUID DEFAULT uuid_generate_v4() -- Anonymous audit ID, not linked to PII directly
);

-- security_events (Optional: for SOC/SIEM integration)
CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID,
    device_id UUID,
    event_type TEXT NOT NULL, -- e.g., 'REUSE_DETECTED', 'OTP_BRUTE_FORCE', 'GEO_ANOMALY'
    event_metadata JSONB DEFAULT '{}', -- Contextual data (e.g., IP, user_agent, detected_location)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
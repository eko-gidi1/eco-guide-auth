-- atomic_refresh_rotate.lua
-- KEYS:
--   KEYS[1] = "refresh:current:" .. family_id             -- Stores the current valid token hash for a family
--   KEYS[2] = "refresh:token:" .. old_hash                -- Metadata for the old token (to mark as revoked or delete)
--   KEYS[3] = "refresh:token:" .. new_hash                -- Metadata for the new token (to create)
--   KEYS[4] = "refresh:prev:" .. old_hash                 -- Marks the old hash as consumed for a grace period for client race conditions

-- ARGV:
--   ARGV[1] = family_id                                   -- The family ID for the token rotation chain
--   ARGV[2] = old_hash                                    -- HMAC_SHA256(KMS_secret, old_refresh_token_raw)
--   ARGV[3] = new_hash                                    -- HMAC_SHA256(KMS_secret, new_refresh_token_raw)
--   ARGV[4] = new_meta_json                               -- JSON string of new token metadata (jti, user_id, device_id, expires_at, etc.)
--   ARGV[5] = new_ttl_seconds                             -- TTL for the new refresh token (e.g., 60 days)
--   ARGV[6] = revocation_message_json                     -- JSON string for the revocation message (if reuse detected)
--   ARGV[7] = prev_grace_ttl_seconds                      -- TTL for the "refresh:prev" key (e.g., 30 seconds)

local current_key = KEYS[1]
local old_token_key = KEYS[2]
local new_token_key = KEYS[3]
local prev_old_hash_marker = KEYS[4] -- Marks the old token hash as having been used

local family_id = ARGV[1]
local old_hash = ARGV[2]
local new_hash = ARGV[3]
local new_meta = ARGV[4]
local new_ttl = tonumber(ARGV[5])
local rev_msg = ARGV[6]
local prev_ttl = tonumber(ARGV[7])

-- Get the current active token hash for this family
local cur_active_hash = redis.call("GET", current_key)

-- --- SCENARIO 1: Normal Rotation ---
-- If the currently active token hash matches the old hash provided by the client,
-- it's a normal rotation request.
if cur_active_hash and cur_active_hash == old_hash then
    -- Atomically create the new token's metadata entry
    -- HSET requires a table, new_meta is a JSON string.
    -- For simplicity, let's assume new_meta_json is directly usable or parsed on client side.
    -- If using HSET, you would pass individual fields as ARGV.
    -- Example using SET for the whole JSON string:
    redis.call("SET", new_token_key, new_meta, "EX", new_ttl)

    -- Update the 'current' marker for the family to the new hash
    redis.call("SET", current_key, new_hash, "EX", new_ttl)

    -- Mark the old token hash as 'used' for a short grace period.
    -- This key helps to detect if an *immediately* subsequent request uses the *old* token,
    -- allowing a short window for concurrent client requests during rotation.
    redis.call("SET", prev_old_hash_marker, "1", "EX", prev_ttl)

    -- We can also immediately delete the old_token_key if we strictly enforce one-time-use.
    -- For strict one-time-use, delete old_token_key immediately after successfully rotating.
    redis.call("DEL", old_token_key) -- Old token metadata is gone.

    return { "OK", "ROTATED" }
end

-- --- SCENARIO 2: Potential Reuse or Invalid Token ---
-- If cur_active_hash is different from old_hash (or old_hash isn't active),
-- it could be a reuse attempt or an invalid/expired token.

-- Check if the old token *ever existed* and is still in Redis, but is not the active one.
-- Or, if the old token is marked as a "previous" token in the grace period (meaning it was just rotated).
local old_token_exists_metadata = redis.call("EXISTS", old_token_key) == 1
local old_token_was_just_rotated = redis.call("EXISTS", prev_old_hash_marker) == 1 -- Check if this old_hash was marked as prev_token

if old_token_exists_metadata or old_token_was_just_rotated then
    -- This indicates a possible reuse of an old or already-rotated token.
    -- IMPORTANT: This triggers a global revocation and incident.
    redis.call("PUBLISH", "revocation:channel", rev_msg) -- Publish to incident channel
    return { err = "REUSE_DETECTED", msg = rev_msg }
end

-- If none of the above, it's an invalid or truly expired token (not part of a known chain/reuse).
return { err = "INVALID_TOKEN" }
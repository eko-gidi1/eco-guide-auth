const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { computeHmacSha256 } = require('../utils/kms_mock');
const RedisClient = require('../utils/redis_mock');
const { sha256hex } = require('../utils/helpers'); // Simple SHA256 helper
const axios = require('axios'); // For calling n8n webhooks

const OTP_TTL = 300; // 5 minutes
const ACCESS_TOKEN_TTL = 900; // 15 minutes
const REFRESH_TOKEN_TTL = 60 * 24 * 60 * 60; // 60 days
const REFRESH_GRACE_PERIOD_TTL = 30; // 30 seconds

// Mock Database (in-memory for simplicity)
const mockDb = {
    users: {}, // { userId: { id, temp_user_id, consented_at, status, devices: [] } }
    refreshTokens: {}, // { tokenHash: { ...metadata } }
    deviceFingerprints: {}, // { deviceId: { userId, userAgentHash, ipLastN, geoAnomalyFlag } }
};

// --- Rate Limiting Mock (simplified) ---
const rateLimits = {
    otpRequest: {
        perIdentifier: { count: 3, window: 10 * 60 }, // 3 requests per 10 mins
        perIp: { count: 5, window: 10 * 60 }, // 5 requests per 10 mins
    },
};

const rateLimitStore = {}; // { key: { count: N, timestamp: TS } }

function checkRateLimit(key, limitConfig) {
    const now = Date.now();
    if (!rateLimitStore[key]) {
        rateLimitStore[key] = { count: 0, timestamp: now };
    }

    const entry = rateLimitStore[key];
    if (now - entry.timestamp > limitConfig.window * 1000) {
        entry.count = 0;
        entry.timestamp = now;
    }

    entry.count++;
    if (entry.count > limitConfig.count) {
        return { limited: true, retryAfter: Math.ceil((entry.timestamp + limitConfig.window * 1000 - now) / 1000) };
    }
    return { limited: false };
}

// --- Internal Auth Helpers ---
function generateRawToken(length = 32) {
    return sha256hex(uuidv4() + Date.now().toString()); // Stronger UUID+timestamp hash
}

function generateMockJwt(userId, deviceId, isAccess = true) {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
        sub: userId,
        dev: deviceId,
        exp: Math.floor(Date.now() / 1000) + (isAccess ? ACCESS_TOKEN_TTL : REFRESH_TOKEN_TTL),
        iat: Math.floor(Date.now() / 1000),
        iss: 'eco-guide-auth',
        aud: isAccess ? 'client-app' : 'auth-service',
        scope: isAccess ? 'read write' : 'refresh',
        jti: uuidv4(),
    })).toString('base64url');

    const signature = computeHmacSha256(process.env.KMS_SECRET, `${header}.${payload}`).toString('base64url');
    return `${header}.${payload}.${signature}`;
}

// --- Endpoints ---

// POST /auth/otp/request
router.post('/otp/request', async (req, res) => {
    const { identifier, channel, temp_user_id, client_ip } = req.body;
    if (!identifier || !channel || !temp_user_id) {
        return res.status(400).json({ status: 'error', message: 'Missing identifier, channel, or temp_user_id' });
    }

    const ipKey = `ip:${client_ip}:otp`;
    const identifierKey = `id:${identifier}:otp`;

    // Apply rate limits
    const ipLimit = checkRateLimit(ipKey, rateLimits.otpRequest.perIp);
    const idLimit = checkRateLimit(identifierKey, rateLimits.otpRequest.perIdentifier);

    if (ipLimit.limited || idLimit.limited) {
        const retryAfter = Math.max(ipLimit.retryAfter || 0, idLimit.retryAfter || 0);
        res.set('Retry-After', retryAfter.toString());
        return res.status(429).json({ status: 'error', message: 'Too many OTP requests. Please try again later.', retry_after_seconds: retryAfter });
    }

    // Call n8n webhook for OTP delivery. n8n will then call our /internal/otp/generate endpoint.
    try {
        await axios.post(process.env.N8N_WEBHOOK_OTP_DELIVERY, {
            identifier,
            channel,
            temp_user_id,
            client_ip,
        });
        res.status(200).json({ status: 'ok', message: 'OTP request processed by n8n for delivery.' });
    } catch (n8nError) {
        console.error('Failed to call n8n OTP delivery webhook:', n8nError.message);
        res.status(500).json({ status: 'error', message: 'OTP request failed (delivery service error).' });
    }
});

// POST /auth/otp/verify
router.post('/otp/verify', async (req, res) => {
    const { identifier, otp, temp_user_id, device_id } = req.body;
    if (!identifier || !otp || !temp_user_id || !device_id) {
        return res.status(400).json({ status: 'error', message: 'Missing identifier, otp, temp_user_id, or device_id' });
    }

    // Retrieve OTP HMAC from Redis
    const storedOtpHmac = await RedisClient.get(`otp:temp:${temp_user_id}`);
    if (!storedOtpHmac) {
        return res.status(400).json({ status: 'error', message: 'OTP expired or not found.' });
    }

    // Verify OTP using constant-time comparison (simulate)
    const providedOtpHmac = computeHmacSha256(process.env.KMS_SECRET, otp).toString('hex');
    if (providedOtpHmac !== storedOtpHmac) { // In a real app, use a constant-time comparison library
        console.warn(`Failed OTP attempt for ${identifier}`);
        // Increment failure counter, potentially block after N attempts
        return res.status(401).json({ status: 'error', message: 'Invalid OTP.' });
    }

    // OTP is valid, consume it
    await RedisClient.del(`otp:temp:${temp_user_id}`);
    console.log(`OTP verified for ${identifier}. Temp user ID: ${temp_user_id}`);

    // Check if user already exists (by temp_user_id mapping or some other identifier)
    // For this mock, assume if `temp_user_id` is here, the user is new until consent.
    // After consent, `temp_user_id` maps to a real `user_id`.
    let user = Object.values(mockDb.users).find(u => u.temp_user_id === temp_user_id);
    let userId;
    if (user) { // User was temporarily created during a previous OTP flow and is pending consent
        userId = user.id;
    } else {
        // This is a completely new OTP flow. Create a new user entry.
        userId = uuidv4();
        mockDb.users[userId] = { id: userId, temp_user_id: temp_user_id, status: 0, devices: [] }; // Status 0: pre-consent
        console.log(`New user created for temp_user_id ${temp_user_id} with real ID ${userId}`);
    }

    // Generate tokens
    const accessToken = generateMockJwt(userId, device_id, true);
    const refreshTokenRaw = generateRawToken();
    const refreshTokenHash = computeHmacSha256(process.env.KMS_SECRET, refreshTokenRaw).toString('hex');

    // Store refresh token metadata in mock DB (and Redis for quick lookup)
    const familyId = uuidv4(); // All tokens in a session belong to a family
    const refreshMeta = {
        jti: uuidv4(),
        family_id: familyId,
        user_id: userId,
        device_id: device_id,
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000).toISOString(),
        prev_token_hash: null, // First token in family
        is_revoked: false,
    };
    mockDb.refreshTokens[refreshTokenHash] = refreshMeta;

    // Update Redis for atomic rotation lookup
    await RedisClient.set(`refresh:current:${familyId}`, refreshTokenHash, 'EX', REFRESH_TOKEN_TTL);
    await RedisClient.hset(`refresh:token:${refreshTokenHash}`, refreshMeta);
    await RedisClient.expire(`refresh:token:${refreshTokenHash}`, REFRESH_TOKEN_TTL);

    res.status(200).json({
        status: 'ok',
        access_token: accessToken,
        expires_in: ACCESS_TOKEN_TTL,
        refresh_token: refreshTokenRaw, // Raw refresh token for client
        user_id: userId,
    });
});

// POST /auth/consent
router.post('/consent', async (req, res) => {
    const { temp_user_id, consent } = req.body;
    if (!temp_user_id || typeof consent !== 'boolean') {
        return res.status(400).json({ status: 'error', message: 'Missing temp_user_id or consent boolean' });
    }

    // Find the user who completed OTP based on temp_user_id
    let user = Object.values(mockDb.users).find(u => u.temp_user_id === temp_user_id);
    if (!user) {
        return res.status(404).json({ status: 'error', message: 'User not found for consent flow.' });
    }

    if (consent) {
        user.consented_at = new Date().toISOString();
        user.status = 1; // Active
        delete user.temp_user_id; // Temp ID no longer needed after consent
        console.log(`User ${user.id} gave consent.`);
        // In a real system, you'd now associate any pending PII from the identifier
        // and finalize the user record.
        res.status(201).json({ status: 'user_created', user_id: user.id });
    } else {
        // User declined consent - delete any temporary data
        delete mockDb.users[user.id]; // Remove user from mock DB
        // Revoke all tokens associated with this user ID (if any were issued before consent)
        for (const hash in mockDb.refreshTokens) {
            if (mockDb.refreshTokens[hash].user_id === user.id) {
                mockDb.refreshTokens[hash].is_revoked = true;
                await RedisClient.del(`refresh:token:${hash}`);
                await RedisClient.del(`refresh:current:${mockDb.refreshTokens[hash].family_id}`);
            }
        }
        console.log(`User ${user.id} declined consent. Temporary data cleared.`);
        res.status(200).json({ status: 'declined', message: 'Consent declined, temporary data cleared.' });
    }
});

// POST /auth/token/refresh
router.post('/token/refresh', async (req, res) => {
    const { refresh_token } = req.body;
    if (!refresh_token) {
        return res.status(400).json({ status: 'error', message: 'Refresh token is missing.' });
    }

    const oldRefreshTokenHash = computeHmacSha256(process.env.KMS_SECRET, refresh_token).toString('hex');

    // Execute atomic refresh rotation via Redis Lua script
    try {
        const familyId = (await RedisClient.hgetall(`refresh:token:${oldRefreshTokenHash}`))?.family_id;
        if (!familyId) {
            console.warn(`Attempt to refresh with unknown or expired token hash: ${oldRefreshTokenHash}`);
            return res.status(401).json({ status: 'error', message: 'Invalid or expired refresh token.' });
        }

        // Generate new raw refresh token and its hash
        const newRefreshTokenRaw = generateRawToken();
        const newRefreshTokenHash = computeHmacSha256(process.env.KMS_SECRET, newRefreshTokenRaw).toString('hex');

        // Prepare new token metadata for Lua script
        const newRefreshMeta = {
            jti: uuidv4(),
            family_id: familyId, // Keep same family_id
            user_id: (await RedisClient.hgetall(`refresh:token:${oldRefreshTokenHash}`))?.user_id,
            device_id: (await RedisClient.hgetall(`refresh:token:${oldRefreshTokenHash}`))?.device_id,
            issued_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000).toISOString(),
            prev_token_hash: oldRefreshTokenHash, // Link to previous token for chain
            is_revoked: false,
        };
        if (!newRefreshMeta.user_id || !newRefreshMeta.device_id) {
             console.error(`Failed to get user_id or device_id from old refresh token metadata for ${oldRefreshTokenHash}.`);
             return res.status(401).json({ status: 'error', message: 'Invalid refresh token metadata.' });
        }

        const luaResult = await RedisClient.atomicRefreshRotate(
            familyId, // KEYS[1] parameter
            oldRefreshTokenHash, // KEYS[2] parameter
            newRefreshTokenHash, // KEYS[3] parameter
            `refresh:prev:${newRefreshTokenHash}`, // KEYS[4] parameter for prev marker
            JSON.stringify(newRefreshMeta), // ARGV[1] = new_meta_json
            REFRESH_TOKEN_TTL, // ARGV[2] = new_ttl_seconds
            JSON.stringify({ // ARGV[3] = revocation_message_json
                event: 'REUSE_DETECTED',
                user_id: newRefreshMeta.user_id,
                device_id: newRefreshMeta.device_id,
                timestamp: new Date().toISOString(),
                reason: 'Refresh token reuse detected by Lua script.',
            }),
            REFRESH_GRACE_PERIOD_TTL // ARGV[4] = prev_grace_ttl_seconds
        );

        if (Array.isArray(luaResult) && luaResult[0] === 'OK' && luaResult[1] === 'ROTATED') {
            // Update mockDb (in a real system, DB would be updated too)
            mockDb.refreshTokens[newRefreshTokenHash] = newRefreshMeta;
            delete mockDb.refreshTokens[oldRefreshTokenHash]; // Old token is consumed

            console.log(`Token family ${familyId} rotated: ${oldRefreshTokenHash} -> ${newRefreshTokenHash}`);

            const newAccessToken = generateMockJwt(newRefreshMeta.user_id, newRefreshMeta.device_id, true);
            return res.status(200).json({
                status: 'ok',
                access_token: newAccessToken,
                expires_in: ACCESS_TOKEN_TTL,
                refresh_token: newRefreshTokenRaw,
                user_id: newRefreshMeta.user_id,
            });
        } else if (luaResult && luaResult.err === 'REUSE_DETECTED') {
            const revMsg = JSON.parse(luaResult.msg);
            console.error(`REUSE_DETECTED by Lua script for user ${revMsg.user_id}.`);
            await axios.post(process.env.N8N_WEBHOOK_REVOKE_INCIDENT, revMsg).catch(e => console.error('Failed to call n8n revoke webhook:', e.message));

            // Perform immediate global revocation in backend for the user
            for (const hash in mockDb.refreshTokens) {
                if (mockDb.refreshTokens[hash].user_id === revMsg.user_id) {
                    mockDb.refreshTokens[hash].is_revoked = true;
                    await RedisClient.del(`refresh:token:${hash}`);
                    await RedisClient.del(`refresh:current:${mockDb.refreshTokens[hash].family_id}`);
                }
            }
            return res.status(401).json({ status: 'error', message: 'Token reuse detected. All sessions revoked. Please re-login.' });
        } else {
            console.error(`Lua script error or invalid token: ${luaResult?.err || 'Unknown error'}`);
            return res.status(401).json({ status: 'error', message: luaResult?.err || 'Token refresh failed.' });
        }
    } catch (error) {
        console.error('Error during Lua script execution or token refresh:', error);
        return res.status(500).json({ status: 'error', message: 'Internal server error during token refresh.' });
    }
});

// POST /auth/token/revoke
router.post('/token/revoke', async (req, res) => {
    // This endpoint can be called by the client (for single device logout)
    // or by n8n (for global logout on reuse detection)
    const { refresh_token, user_id, device_id } = req.body;

    if (req.headers['x-internal-api-key'] === process.env.INTERNAL_API_KEY && user_id) {
        // Internal call (e.g., from n8n for global revoke)
        console.warn(`INTERNAL: Global revoke initiated for user ${user_id}.`);
        for (const hash in mockDb.refreshTokens) {
            if (mockDb.refreshTokens[hash].user_id === user_id) {
                mockDb.refreshTokens[hash].is_revoked = true;
                await RedisClient.del(`refresh:token:${hash}`);
                await RedisClient.del(`refresh:current:${mockDb.refreshTokens[hash].family_id}`);
            }
        }
        return res.status(200).json({ status: 'ok', message: `All sessions revoked for user ${user_id}.` });
    } else if (refresh_token) {
        // Client-initiated revoke (single device logout)
        const tokenHash = computeHmacSha256(process.env.KMS_SECRET, refresh_token).toString('hex');
        const tokenMeta = mockDb.refreshTokens[tokenHash]; // Check in mockDb (or Redis if more robust)

        if (tokenMeta) {
            tokenMeta.is_revoked = true;
            await RedisClient.del(`refresh:token:${tokenHash}`);
            await RedisClient.del(`refresh:current:${tokenMeta.family_id}`); // Invalidate the current marker for this family
            console.log(`Client-initiated revoke for token ${tokenHash}, user ${tokenMeta.user_id}.`);
        } else {
            console.warn(`Client tried to revoke unknown or already revoked token: ${tokenHash}`);
        }
        return res.status(200).json({ status: 'ok', message: 'Token revoked (if found).' });
    } else {
        return res.status(400).json({ status: 'error', message: 'Missing token or valid revocation criteria.' });
    }
});

// POST /auth/introspect
router.post('/introspect', async (req, res) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ status: 'error', message: 'Token is missing.' });
    }

    // Mock introspection: Assume if token is present, it's valid for now
    // A real introspection would check DB/Redis for opaque token status or parse JWT validity.
    // For JWTs, you'd decode and verify. For opaque, lookup in DB.
    if (token.startsWith('eyJ')) { // Simple check for JWT
        try {
            const parts = token.split('.');
            const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
            const isActive = payload.exp > Math.floor(Date.now() / 1000);
            return res.status(200).json({
                active: isActive,
                user_id: payload.sub,
                device_id: payload.dev,
                exp: payload.exp,
                scope: payload.scope,
            });
        } catch (e) {
            return res.status(200).json({ active: false, message: 'Invalid JWT format.' });
        }
    } else {
        // Assume opaque token
        const tokenHash = computeHmacSha256(process.env.KMS_SECRET, token).toString('hex');
        const tokenMeta = await RedisClient.hgetall(`refresh:token:${tokenHash}`);
        const isActive = tokenMeta && tokenMeta.is_revoked !== 'true' && new Date() < new Date(tokenMeta.expires_at);

        if (isActive) {
             return res.status(200).json({
                active: true,
                user_id: tokenMeta.user_id,
                device_id: tokenMeta.device_id,
                exp: Math.floor(new Date(tokenMeta.expires_at).getTime() / 1000),
                // Add other scopes/claims as appropriate
            });
        }
        return res.status(200).json({ active: false });
    }
});


module.exports = router;
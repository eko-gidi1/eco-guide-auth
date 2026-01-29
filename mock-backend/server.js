require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const authRoutes = require('./routes/auth');
const RedisClient = require('./utils/redis_mock');
const { initRedisLuaScripts } = require('./utils/redis_mock');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration (adjust for production)
app.use(cors({
    origin: '*', // Allow all origins for development. In production, specify your Flutter app's domain.
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Internal-API-Key'],
}));

app.use(bodyParser.json());

// Middleware to simulate `server_time` synchronization
app.use((req, res, next) => {
    res.set('X-Server-Time', new Date().toISOString());
    next();
});

// Initialize Redis client and load Lua scripts
(async () => {
    try {
        await RedisClient.connect();
        await initRedisLuaScripts();
        console.log('Redis connected and Lua scripts loaded.');
    } catch (error) {
        console.error('Failed to connect to Redis or load Lua scripts:', error);
        process.exit(1); // Exit if Redis fails
    }
})();

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', server_time: new Date().toISOString() });
});

// Auth API routes
app.use('/auth', authRoutes);

// Internal API endpoint for n8n to call for OTP generation
// This endpoint requires an internal API key for security
app.post('/internal/otp/generate', async (req, res) => {
    const internalApiKey = req.headers['x-internal-api-key'];
    if (internalApiKey !== process.env.INTERNAL_API_KEY) {
        console.warn('Unauthorized internal access attempt to /internal/otp/generate');
        return res.status(401).json({ status: 'error', message: 'Unauthorized internal access' });
    }
    // Call the OTP generation logic from authRoutes directly
    // This part is tricky because Express router is middleware.
    // A better approach would be to extract the OTP generation logic into a separate service function.
    // For this mock, we'll simulate the call and return a mock OTP.
    const { identifier, channel, temp_user_id, client_ip } = req.body;
    if (!identifier || !channel || !temp_user_id) {
        return res.status(400).json({ status: 'error', message: 'Missing identifier, channel, or temp_user_id' });
    }

    // Simplified mock: In a real scenario, the authRoutes.js logic would be reused.
    // We mock success for n8n to proceed with delivery.
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
    const otpHmac = require('./utils/kms_mock').computeHmacSha256(process.env.KMS_SECRET, otpCode).toString('hex');
    await RedisClient.set(`otp:temp:${temp_user_id}`, otpHmac, 'EX', 300); // 5 minutes TTL

    console.log(`INTERNAL: Generated OTP for ${identifier}: ${otpCode} (HMAC stored, ready for n8n delivery)`);
    res.status(200).json({ status: 'ok', otp_code: otpCode, otp_message: `Your ECO-GUIDE verification code is: ${otpCode}. Valid for 5 minutes.` });
});


// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(PORT, () => {
    console.log(`Mock Backend running on http://localhost:${PORT}`);
});
const crypto = require('crypto');

// This mocks AWS KMS GenerateMac. In a real app, you'd use AWS SDK or similar.
function computeHmacSha256(secret, data) {
    if (!secret || !data) {
        throw new Error('KMS_MOCK: Secret and data are required for HMAC computation.');
    }
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(data);
    return hmac.digest(); // Returns a Buffer
}

module.exports = {
    computeHmacSha256,
};
const crypto = require('crypto');

function sha256hex(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = {
    sha256hex,
};
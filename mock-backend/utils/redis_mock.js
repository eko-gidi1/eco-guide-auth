const Redis = require('ioredis');
const fs = require('fs');
const path = require('path');

const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:6379');

let luaScriptsSha = {}; // To store SHA1 of loaded scripts for EVALSHA

async function connect() {
    return new Promise((resolve, reject) => {
        redis.on('connect', () => {
            console.log('Redis client connected');
            resolve();
        });
        redis.on('error', (err) => {
            console.error('Redis error:', err);
            reject(err);
        });
    });
}

async function initRedisLuaScripts() {
    const scriptContent = fs.readFileSync(path.join(__dirname, '../lua/atomic_refresh_rotate.lua'), 'utf8');
    luaScriptsSha.atomicRefreshRotate = await redis.script('LOAD', scriptContent);
    console.log(`Loaded atomic_refresh_rotate.lua, SHA: ${luaScriptsSha.atomicRefreshRotate}`);

    // Define the custom command so we can call it directly like redis.atomicRefreshRotate(...)
    redis.defineCommand('atomicRefreshRotate', {
        numberOfKeys: 4, // KEYS[1] = refresh:current:<family_id>, KEYS[2]=refresh:token:<old_hash>, KEYS[3]=refresh:token:<new_hash>, KEYS[4]=refresh:prev:<new_hash>
        lua: scriptContent // Provide the script content directly, ioredis will load it if needed
    });
}

module.exports = {
    connect,
    initRedisLuaScripts,
    ...redis, // Expose all ioredis methods
};
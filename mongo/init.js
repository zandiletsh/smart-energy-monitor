db = db.getSiblingDB("energy_monitor");

const collections = [
  "users", "devices", "subscriptions", "user_settings",
  "energy_readings", "anomalies", "revoked_tokens",
  "password_reset_tokens", "email_verification_tokens"
];
collections.forEach(c => { try { db.createCollection(c); } catch(e) {} });

// TTL index — auto-expire revoked tokens after their JWT expiry
db.revoked_tokens.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });
// TTL index — auto-expire password reset tokens
db.password_reset_tokens.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });
// TTL index — auto-expire old readings (per-document expires_at field)
db.energy_readings.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });
// Composite index for fast per-device queries
db.energy_readings.createIndex({ "device_key": 1, "timestamp": -1 });
db.energy_readings.createIndex({ "user_id": 1, "timestamp": -1 });

print("energy_monitor initialised with all collections and TTL indexes.");

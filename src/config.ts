// src/config.ts

// SMS settings
export const SMS_EXPIRY_DURATION_MINUTES = 300;

// API settings
export const API_GLOBAL_COOLDOWN_SECONDS = 5;

// JWT settings
export const JWT_EXPIRY_MINUTES = 5;

// Cloudflare KV Store keys
export const KV_KEY_SMS_MESSAGES = "all_sms_messages";
export const KV_KEY_LAST_DB_OP_TIMESTAMP = "last_db_op_timestamp"; 
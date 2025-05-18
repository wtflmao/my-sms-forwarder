// src/env.d.ts

// This interface defines the bindings and environment variables
// that will be available in your Worker via the `c.env` object in Hono.
export interface Env {
  // KV Namespace binding (from wrangler.toml)
  SMS_DB_KV: KVNamespace;

  // Environment variables / secrets (from wrangler.toml vars or secrets)
  CLOUDFLARE_TURNSTILE_SECRET_KEY: string;
  WEBHOOK_SECRET: string;
  JWT_SECRET: string;

  // You can add other bindings or environment variables here if needed
  // e.g., MY_OTHER_VAR: string;
} 
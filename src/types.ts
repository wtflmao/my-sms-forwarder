// src/types.ts
export interface SMSEntry {
  id: string;
  payload: any; // Consider defining a more specific type for your SMS payload
  receivedAt: number; // Unix timestamp in milliseconds
  source?: string; // Optional: sender info or any identifier for the source
}

export interface WebhookPayload {
  // This is an EXAMPLE structure. Adjust it to the actual payload your webhook source sends.
  from?: string;
  text: string;
  timestamp?: string; // Timestamp from the source, if available
  // Add any other fields your webhook might send
}

export interface TurnstileVerificationResponse {
  success: boolean;
  'error-codes'?: string[];
  challenge_ts?: string; // ISO_8601_FULL_DATETIME
  hostname?: string;
  action?: string;
  cdata?: string;
}

export interface JWTPayload {
  verified: true;
  iat: number; // Issued at (Unix timestamp in seconds)
  exp: number; // Expiration time (Unix timestamp in seconds)
} 
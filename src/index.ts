/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { Hono } from 'hono';
import { setCookie, getCookie } from 'hono/cookie'; // Added getCookie
import { sign, verify } from '@tsndr/cloudflare-worker-jwt'; // Will be used later
import type { Env } from './env';
import type { SMSEntry, WebhookPayload, JWTPayload, TurnstileVerificationResponse } from './types'; // Added TurnstileVerificationResponse
import { 
    API_GLOBAL_COOLDOWN_SECONDS,
    JWT_EXPIRY_MINUTES,
    KV_KEY_LAST_DB_OP_TIMESTAMP,
    KV_KEY_SMS_MESSAGES,
    SMS_EXPIRY_DURATION_MINUTES
} from './config';

// Initialize Hono app with Env types
const app = new Hono<{ Bindings: Env }>();

// Middleware for Webhook Secret Validation
app.use('/webhook/sms', async (c, next) => {
    const providedSecret = c.req.header('X-Webhook-Secret');
    if (!c.env.WEBHOOK_SECRET) {
        console.error('WEBHOOK_SECRET is not set in environment variables.');
        return c.json({ error: 'Configuration error: Webhook secret not set on server' }, 500);
    }
    if (providedSecret !== c.env.WEBHOOK_SECRET) {
        return c.json({ error: 'Unauthorized: Invalid webhook secret' }, 401);
    }
    await next();
});

app.get('/', (c) => {
	return c.text('Hello from SMS Forwarder Backend!');
});

// 5. Webhook SMS Receiver Endpoint
app.post('/webhook/sms', async (c) => { // Middleware is applied via app.use above
    try {
        const body = await c.req.json<WebhookPayload>();

        // Basic payload validation (Adjust based on actual payload structure)
        if (!body || typeof body.text !== 'string') {
            return c.json({ error: 'Invalid payload: text field is required and must be a string' }, 400);
        }

        const newId = crypto.randomUUID();
        const receivedAt = Date.now();

        const newSMSEntry: SMSEntry = {
            id: newId,
            payload: body, // Store the whole payload as received
            receivedAt: receivedAt,
            source: body.from || 'unknown', // Example: use 'from' field if available
        };

        // Get existing messages or initialize if not present
        let messages: SMSEntry[] = await c.env.SMS_DB_KV.get<SMSEntry[]>(KV_KEY_SMS_MESSAGES, 'json') || [];
        
        messages.push(newSMSEntry);

        // Store updated messages array
        await c.env.SMS_DB_KV.put(KV_KEY_SMS_MESSAGES, JSON.stringify(messages));

        return c.json({ success: true, messageId: newId }, 201);

    } catch (e: any) {
        console.error('Error processing webhook:', e.message);
        if (e instanceof SyntaxError) { // Catch JSON parsing errors specifically
            return c.json({ error: 'Invalid JSON payload' }, 400);
        }
        return c.json({ error: 'Failed to process webhook' }, 500);
    }
});

// JWT Authentication Middleware (Step 7.2)
const jwtAuth = async (c: any, next: any) => {
    const token = getCookie(c, 'auth_token');

    if (!token) {
        return c.json({ error: 'Unauthorized: Missing authentication token' }, 401);
    }

    if (!c.env.JWT_SECRET) {
        console.error('JWT_SECRET is not set in environment variables.');
        return c.json({ error: 'Configuration error: JWT secret not set on server' }, 500);
    }

    try {
        const decoded = await verify(token, c.env.JWT_SECRET) as { payload: JWTPayload }; // Type assertion for payload
        if (!decoded || !decoded.payload || !decoded.payload.verified) {
            return c.json({ error: 'Unauthorized: Invalid token or verification missing' }, 401);
        }
        // Optionally, you can pass parts of the decoded payload to subsequent handlers if needed
        // c.set('jwtUser', decoded.payload.user); // Example if JWT contained user info
    } catch (e: any) {
        if (e.message.includes('expired')) {
            return c.json({ error: 'Unauthorized: Token expired' }, 401);
        }
        console.error('JWT verification error:', e.message);
        return c.json({ error: 'Unauthorized: Token verification failed' }, 401);
    }
    await next();
};

// 6. Cloudflare Turnstile Verification Endpoint
app.post('/api/verify-captcha', async (c) => {
    try {
        const body = await c.req.json<{ token: string }>();
        const token = body?.token;

        if (!token) {
            return c.json({ error: 'Turnstile token is required' }, 400);
        }

        if (!c.env.CLOUDFLARE_TURNSTILE_SECRET_KEY) {
            console.error('CLOUDFLARE_TURNSTILE_SECRET_KEY is not set.');
            return c.json({ error: 'Turnstile configuration error on server' }, 500);
        }

        const verifyEndpoint = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        const verificationResponse = await fetch(verifyEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                secret: c.env.CLOUDFLARE_TURNSTILE_SECRET_KEY,
                response: token,
            }),
        });

        const outcome = await verificationResponse.json<TurnstileVerificationResponse>();

        if (outcome.success) {
            if (!c.env.JWT_SECRET) {
                console.error('JWT_SECRET is not set.');
                return c.json({ error: 'JWT configuration error on server' }, 500);
            }
            const now = Math.floor(Date.now() / 1000); // Unix timestamp in seconds
            const jwtPayload: JWTPayload = {
                verified: true,
                iat: now,
                exp: now + (JWT_EXPIRY_MINUTES * 60),
            };
            const signedToken = await sign(jwtPayload, c.env.JWT_SECRET);

            setCookie(c, 'auth_token', signedToken, {
                httpOnly: true,
                secure: c.req.url.startsWith('https://'), // Set Secure if on HTTPS
                path: '/',
                sameSite: 'Lax', // Or 'Strict'
                maxAge: JWT_EXPIRY_MINUTES * 60, // Cookie expiry in seconds
            });
            return c.json({ success: true, message: 'Turnstile verification successful. JWT set.' });
        } else {
            return c.json({ success: false, error: 'Turnstile verification failed', 'error-codes': outcome['error-codes'] }, 401);
        }
    } catch (e: any) {
        console.error('Error in /api/verify-captcha:', e.message);
        return c.json({ error: 'Failed to verify Turnstile token' }, 500);
    }
});

// Apply JWT Auth middleware to /api/sms route
app.use('/api/sms', jwtAuth);

// 7. SMS Data Retrieval Endpoint
app.get('/api/sms', async (c) => { // jwtAuth middleware is now applied via app.use
    // Global Cooldown Check (Step 7.3)
    const lastOpTimestamp = await c.env.SMS_DB_KV.get<number>(KV_KEY_LAST_DB_OP_TIMESTAMP, 'json');
    if (lastOpTimestamp && (Date.now() - lastOpTimestamp) < (API_GLOBAL_COOLDOWN_SECONDS * 1000)) {
        // Return 204 No Content, or the last known good data if we decide to cache it at this layer
        // For now, 204 indicates to client "no change due to cooldown"
        return new Response(null, { status: 204 }); 
    }

    // Data Processing (Step 7.4)
    try {
        let messages: SMSEntry[] = await c.env.SMS_DB_KV.get<SMSEntry[]>(KV_KEY_SMS_MESSAGES, 'json') || [];
        
        const now = Date.now();
        const expiryTime = SMS_EXPIRY_DURATION_MINUTES * 60 * 1000;

        const validMessages = messages.filter(msg => (now - msg.receivedAt) < expiryTime);

        // Check if messages were actually filtered to avoid unnecessary KV write
        if (validMessages.length < messages.length) {
            await c.env.SMS_DB_KV.put(KV_KEY_SMS_MESSAGES, JSON.stringify(validMessages));
            messages = validMessages;
        }
        
        // Update last operation timestamp if actual DB read/write occurred for sms list
        // (excluding cooldowns which don't reach this point for writes)
        await c.env.SMS_DB_KV.put(KV_KEY_LAST_DB_OP_TIMESTAMP, JSON.stringify(Date.now()));

        return c.json(messages);

    } catch (e: any) {
        console.error('Error in /api/sms:', e.message);
        return c.json({ error: 'Failed to retrieve SMS messages' }, 500);
    }
});

export default app;

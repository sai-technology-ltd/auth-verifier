import { createRemoteJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { createApp } from './app.js';

const envSchema = z.object({
  PORT: z.coerce.number().default(3001),
  LOG_LEVEL: z.enum(['error', 'warn', 'info']).default('info'),
  SUPABASE_ISSUER: z.string().url(),
  SUPABASE_JWKS_URL: z.string().url().optional(),
  SUPABASE_AUDIENCE: z.string().optional(),
  FORWARDED_USER_ID_HEADER: z.string().default('x-user-id'),
  FORWARDED_ROLE_HEADER: z.string().default('x-user-role'),
  TRUSTED_PROXY_IPS: z.string().optional(),
});

const env = envSchema.parse(process.env);
const jwksUrl = env.SUPABASE_JWKS_URL || `${env.SUPABASE_ISSUER}/.well-known/jwks.json`;
const JWKS = createRemoteJWKSet(new URL(jwksUrl));

const trustedProxyIps = env.TRUSTED_PROXY_IPS
  ? env.TRUSTED_PROXY_IPS.split(',').map((x) => x.trim()).filter(Boolean)
  : undefined;

const LOG_LEVEL_ORDER: Record<'error' | 'warn' | 'info', number> = {
  error: 0,
  warn: 1,
  info: 2,
};

function log(level: 'error' | 'warn' | 'info', message: string, meta: Record<string, unknown> = {}) {
  if (LOG_LEVEL_ORDER[level] > LOG_LEVEL_ORDER[env.LOG_LEVEL]) return;
  const payload = {
    ts: new Date().toISOString(),
    level,
    message,
    ...meta,
  };
  const line = JSON.stringify(payload);
  if (level === 'error') {
    console.error(line);
    return;
  }
  if (level === 'warn') {
    console.warn(line);
    return;
  }
  console.log(line);
}

const app = createApp({
  forwardedUserIdHeader: env.FORWARDED_USER_ID_HEADER,
  forwardedRoleHeader: env.FORWARDED_ROLE_HEADER,
  trustedProxyIps,
  log,
  verifyJwt: async (token: string) => {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: env.SUPABASE_ISSUER,
      audience: env.SUPABASE_AUDIENCE || undefined,
    });
    return payload;
  },
});

app.listen(env.PORT, () => {
  log('info', 'auth-verifier listening', {
    port: env.PORT,
    issuer: env.SUPABASE_ISSUER,
    jwksUrl,
    audience: env.SUPABASE_AUDIENCE || null,
    trustedProxyIps: trustedProxyIps || [],
    logLevel: env.LOG_LEVEL,
  });
});

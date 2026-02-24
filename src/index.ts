import { createRemoteJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { createApp } from './app.js';

const envSchema = z.object({
  PORT: z.coerce.number().default(3001),
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

const app = createApp({
  forwardedUserIdHeader: env.FORWARDED_USER_ID_HEADER,
  forwardedRoleHeader: env.FORWARDED_ROLE_HEADER,
  trustedProxyIps,
  verifyJwt: async (token: string) => {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: env.SUPABASE_ISSUER,
      audience: env.SUPABASE_AUDIENCE || undefined,
    });
    return payload;
  },
});

app.listen(env.PORT, () => {
  console.log(`auth-verifier listening on :${env.PORT}`);
});

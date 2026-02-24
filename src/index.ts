import express from 'express';
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';
import { z } from 'zod';

const envSchema = z.object({
  PORT: z.coerce.number().default(3001),
  SUPABASE_ISSUER: z.string().url(),
  SUPABASE_JWKS_URL: z.string().url().optional(),
  SUPABASE_AUDIENCE: z.string().optional(),
  FORWARDED_USER_ID_HEADER: z.string().default('x-user-id'),
  FORWARDED_ROLE_HEADER: z.string().default('x-user-role'),
  FORWARDED_PERMISSIONS_HEADER: z.string().default('x-user-permissions'),
});

const env = envSchema.parse(process.env);

const jwksUrl = env.SUPABASE_JWKS_URL || `${env.SUPABASE_ISSUER}/.well-known/jwks.json`;
const JWKS = createRemoteJWKSet(new URL(jwksUrl));

const app = express();

function getBearer(req: express.Request): string | null {
  const auth = req.header('authorization');
  if (!auth) return null;
  const [type, token] = auth.split(' ');
  if (type?.toLowerCase() !== 'bearer' || !token) return null;
  return token;
}

function roleFromClaims(payload: JWTPayload): string {
  const metadata = payload.user_metadata as Record<string, unknown> | undefined;
  const appMeta = payload.app_metadata as Record<string, unknown> | undefined;
  const role = (appMeta?.role || metadata?.role || payload.role) as string | undefined;
  return role || 'user';
}

function permsFromClaims(payload: JWTPayload): string[] {
  const appMeta = payload.app_metadata as Record<string, unknown> | undefined;
  const perms = appMeta?.permissions;
  if (Array.isArray(perms)) return perms.map(String);
  return [];
}

async function verify(req: express.Request, res: express.Response) {
  try {
    const token = getBearer(req);
    if (!token) return res.status(401).json({ ok: false, error: 'Missing bearer token' });

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: env.SUPABASE_ISSUER,
      audience: env.SUPABASE_AUDIENCE || undefined,
    });

    const userId = String(payload.sub || '');
    if (!userId) return res.status(401).json({ ok: false, error: 'Invalid subject claim' });

    const role = roleFromClaims(payload);
    const permissions = permsFromClaims(payload);

    res.setHeader(env.FORWARDED_USER_ID_HEADER, userId);
    res.setHeader(env.FORWARDED_ROLE_HEADER, role);
    res.setHeader(env.FORWARDED_PERMISSIONS_HEADER, permissions.join(','));

    return res.status(200).json({ ok: true, userId, role });
  } catch (err: any) {
    return res.status(401).json({ ok: false, error: 'Unauthorized', detail: err?.message || 'invalid_token' });
  }
}

app.get('/health', (_req, res) => res.status(200).json({ ok: true }));
app.get('/verify', verify);
app.post('/verify', verify);

app.listen(env.PORT, () => {
  console.log(`auth-verifier listening on :${env.PORT}`);
});

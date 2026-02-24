import express from 'express';
import { JWTPayload } from 'jose';

export type VerifyJwtFn = (token: string) => Promise<JWTPayload>;

type AppConfig = {
  verifyJwt: VerifyJwtFn;
  forwardedUserIdHeader: string;
  forwardedRoleHeader: string;
  trustedProxyIps?: string[];
};

function normalizeIp(ip?: string | null): string {
  if (!ip) return '';
  return ip.replace('::ffff:', '').trim();
}

function firstForwardedIp(header?: string): string {
  if (!header) return '';
  return normalizeIp(header.split(',')[0]);
}

function roleFromClaims(payload: JWTPayload): string {
  const metadata = payload.user_metadata as Record<string, unknown> | undefined;
  const appMeta = payload.app_metadata as Record<string, unknown> | undefined;
  const role = (appMeta?.role || metadata?.role || payload.role) as string | undefined;
  return role || 'user';
}

function getBearer(auth?: string): string | null {
  if (!auth) return null;
  const [type, token] = auth.split(' ');
  if (type?.toLowerCase() !== 'bearer' || !token) return null;
  return token;
}

export function createApp(cfg: AppConfig) {
  const app = express();

  app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

  app.get('/verify', async (req, res) => {
    try {
      if (cfg.trustedProxyIps && cfg.trustedProxyIps.length > 0) {
        const fromHeader = firstForwardedIp(req.header('x-forwarded-for') || undefined);
        const fromSocket = normalizeIp(req.socket.remoteAddress);
        const source = fromHeader || fromSocket;
        if (!cfg.trustedProxyIps.includes(source)) {
          return res.status(403).json({ ok: false, error: 'Forbidden source' });
        }
      }

      const token = getBearer(req.header('authorization') || undefined);
      if (!token) return res.status(401).json({ ok: false, error: 'Missing bearer token' });

      const payload = await cfg.verifyJwt(token);
      const userId = String(payload.sub || '');
      if (!userId) return res.status(401).json({ ok: false, error: 'Invalid subject claim' });

      const role = roleFromClaims(payload);
      res.setHeader(cfg.forwardedUserIdHeader, userId);
      res.setHeader(cfg.forwardedRoleHeader, role);
      return res.status(200).json({ ok: true, userId, role });
    } catch (err: any) {
      return res.status(401).json({ ok: false, error: 'Unauthorized', detail: err?.message || 'invalid_token' });
    }
  });

  return app;
}

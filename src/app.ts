import express from 'express';
import { randomUUID } from 'node:crypto';
import { JWTPayload } from 'jose';

export type VerifyJwtFn = (token: string) => Promise<JWTPayload>;

type AppConfig = {
  verifyJwt: VerifyJwtFn;
  forwardedUserIdHeader: string;
  forwardedRoleHeader: string;
  trustedProxyIps?: string[];
  log?: (level: 'info' | 'warn' | 'error', message: string, meta?: Record<string, unknown>) => void;
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
  const log = cfg.log || (() => undefined);

  app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

  app.get('/verify', async (req, res) => {
    const requestId = req.header('x-request-id') || randomUUID();
    const sourceIp = firstForwardedIp(req.header('x-forwarded-for') || undefined) || normalizeIp(req.socket.remoteAddress);
    const authorization = req.header('authorization') || '';

    log('info', 'verify request', {
      requestId,
      sourceIp,
      method: req.header('x-forwarded-method') || req.method,
      uri: req.header('x-forwarded-uri') || req.originalUrl,
      hasAuthorizationHeader: Boolean(authorization),
      authorizationScheme: authorization ? authorization.split(' ')[0] : undefined,
      host: req.header('x-forwarded-host') || req.header('host'),
      origin: req.header('origin'),
    });

    try {
      if (cfg.trustedProxyIps && cfg.trustedProxyIps.length > 0) {
        const source = sourceIp;
        if (!cfg.trustedProxyIps.includes(source)) {
          log('warn', 'verify blocked by trusted proxy ip list', { requestId, sourceIp });
          return res.status(403).json({ ok: false, error: 'Forbidden source' });
        }
      }

      const token = getBearer(authorization || undefined);
      if (!token) {
        log('warn', 'verify missing bearer token', { requestId, sourceIp });
        return res.status(401).json({ ok: false, error: 'Missing bearer token' });
      }

      const payload = await cfg.verifyJwt(token);
      const userId = String(payload.sub || '');
      if (!userId) {
        log('warn', 'verify invalid subject claim', { requestId, sourceIp });
        return res.status(401).json({ ok: false, error: 'Invalid subject claim' });
      }

      const role = roleFromClaims(payload);
      res.setHeader(cfg.forwardedUserIdHeader, userId);
      res.setHeader(cfg.forwardedRoleHeader, role);
      log('info', 'verify success', { requestId, sourceIp, userId, role });
      return res.status(200).json({ ok: true, userId, role });
    } catch (err: any) {
      log('warn', 'verify unauthorized', {
        requestId,
        sourceIp,
        errorName: err?.name,
        errorMessage: err?.message,
      });
      return res.status(401).json({ ok: false, error: 'Unauthorized', detail: err?.message || 'invalid_token' });
    }
  });

  return app;
}

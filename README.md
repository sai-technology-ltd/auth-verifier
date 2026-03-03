# auth-verifier

Standalone JWT verification service for Traefik ForwardAuth.

It validates Supabase access tokens using JWKS and, on success, forwards minimal trusted identity headers to downstream services.

## What it does
- Verifies `Authorization: Bearer <token>`
- Validates token signature against Supabase JWKS
- Validates issuer (`SUPABASE_ISSUER`)
- Optionally validates audience (`SUPABASE_AUDIENCE`)
- Returns 401 for invalid/missing tokens
- Returns 200 and sets identity headers for valid tokens

## Endpoints
- `GET /health`
- `GET /verify`

## Forwarded headers (success)
- `x-user-id`
- `x-user-role`

## Environment
Copy `.env.example` and set:
- `SUPABASE_ISSUER` (required)
- `SUPABASE_AUDIENCE` (optional)
- `SUPABASE_JWKS_URL` (optional; defaults to `${SUPABASE_ISSUER}/.well-known/jwks.json`)
- `PORT` (default `3001`)
- `LOG_LEVEL` (`error` | `warn` | `info`, default `info`)
- `TRUSTED_PROXY_IPS` (optional comma-separated allowlist for caller source IP)

## Local development
```bash
npm install
npm run dev
```

## Test
```bash
npm test
```

## Build & run
```bash
npm run build
npm start
```

## Docker
```bash
docker build -t shareef945/auth-verifier:local .
docker run --rm -p 3001:3001 --env-file .env shareef945/auth-verifier:local
```

## Traefik (OSS) middleware example
```yaml
http:
  middlewares:
    swift-jwt-forwardauth:
      forwardAuth:
        address: "http://auth-verifier:3001/verify"
        trustForwardHeader: true
        authResponseHeaders:
          - X-User-Id
          - X-User-Role
```

## CI/CD
GitHub Actions workflow is included at:
- `.github/workflows/ci-cd.yml`

It builds and pushes multi-arch images to:
- `shareef945/auth-verifier` (`linux/amd64`, `linux/arm64`)

Required repo secrets:
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

## Troubleshooting auth failures
- Check verifier logs for `verify request`, `verify missing bearer token`, `verify unauthorized`, or `verify success`.
- Confirm `SUPABASE_ISSUER` matches token `iss` exactly (including path and trailing slash behavior).
- If `SUPABASE_AUDIENCE` is set, confirm it matches token `aud` (Supabase is often `authenticated`).
- In Traefik `forwardAuth`, explicitly forward the auth header if needed:

```yaml
forwardAuth:
  address: "http://auth-verifier:3001/verify"
  trustForwardHeader: true
  authRequestHeaders:
    - Authorization
```

# auth-verifier

JWT verifier service for Traefik ForwardAuth, validating Supabase access tokens using JWKS.

## Endpoints
- `GET /health`
- `GET /verify`
- `POST /verify`

`/verify` expects `Authorization: Bearer <token>` and returns:
- `200` + headers (`x-user-id`, `x-user-role`, `x-user-permissions`) when valid
- `401` when invalid

## Env
Copy `.env.example` and set:
- `SUPABASE_ISSUER` (required)
- `SUPABASE_AUDIENCE` (optional but recommended)
- `SUPABASE_JWKS_URL` (optional)

## Local run
```bash
npm install
npm run dev
```

## Build
```bash
npm run build
npm start
```

## Traefik middleware example
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
          - X-User-Permissions
```
# auth-verifier

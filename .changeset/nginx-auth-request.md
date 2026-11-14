---
"sekisho": minor
---

Add `"mode": "auth_request"`, which lets Sekisho act as the decision service for nginx `auth_request` (and Traefik `forwardAuth` or Caddy `forward_auth`) instead of proxying. Sekisho reads the original method and URI from `X-Original-Method` and `X-Original-URI`, applies the same routing, OIDC verification and policies, and returns `X-Sekisho-Authorization` with the route's backend credential. Denials are mapped to 401 or 403, and the original status is kept in `X-Sekisho-Status`.

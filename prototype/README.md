# MIF prototype: private-mesh profile

A local simulation of one MIF node, built to prove the [private-mesh profile](../docs/profiles/private-mesh.md): sign in through an upstream identity provider, lose that provider, keep signing in with a passkey under restrictions, and return to normal when it comes back.

Nothing here talks to Microsoft. A second Keycloak plays the part of Entra so that the outage can be switched on and off.

## What runs

| Service | Port | Role |
|---|---|---|
| `keycloak` | 8080 | The MIF broker: federates the upstream, holds passkeys, issues tokens |
| `fake-entra` | 8090 | Stand-in for Entra. Stop it to simulate the outage |
| `mif-node` | 8088, 8081 (loopback) | Snapshot service and continuity controller (ASP.NET Core) |
| `demo-portal` | 5080 | Example application that trusts only the MIF node |
| `postgres` | internal | State for the broker and the node |

## Run it

Requires Docker with Compose.

```bash
cd prototype
docker compose up -d --build
```

First start takes about a minute. The node may report `Degraded` for a few seconds while the upstream container boots; wait until <http://localhost:8088/status> shows `"mode":"Normal"`.

### Walk through an outage by hand

Use a browser with a passkey provider (Windows Hello, Touch ID, a phone, or a security key).

1. Open <http://localhost:5080> and sign in as `alice` / `alice-dev-only`. The portal shows a **LIVE** session.
2. Choose **Enrol a passkey for outages** and register one.
3. Stop the upstream: `docker compose stop fake-entra`. Within about ten seconds `/status` reports `Degraded`.
4. Sign out, then sign in again. The sign-in page now offers only the passkey. The portal shows a **CONTINUITY** session.
5. **View records** works. **Approve payment** is refused with 403, although Alice still holds the role.
6. Bring the upstream back: `docker compose start fake-entra`. The node returns to `Normal` and ends all sessions; the next sign-in goes through the upstream again.

`bob` / `bob-dev-only` is a second user without the approver role.

### Operator commands

The operator port is bound to loopback. In a deployment you would reach it over SSH.

```bash
# Who holds a snapshot, and until when
curl -s localhost:8081/operator/snapshots

# Revoke a user for the rest of the outage
curl -s -X POST localhost:8081/operator/revoke -H 'content-type: application/json' \
  -d '{"username":"alice","reason":"laptop reported stolen"}'

# Force degraded mode (a drill, or an outage the probes cannot see), then release it
curl -s -X POST localhost:8081/operator/mode -H 'content-type: application/json' \
  -d '{"override":"ForceDegraded","reason":"quarterly drill"}'
curl -s -X POST localhost:8081/operator/mode -H 'content-type: application/json' \
  -d '{"override":"Auto","reason":"drill over"}'

# Audit trail, with a check that its hash chain is intact
curl -s 'localhost:8081/operator/audit?max=50'
```

From PowerShell, use `Invoke-RestMethod`:

```powershell
Invoke-RestMethod http://localhost:8081/operator/snapshots
Invoke-RestMethod -Method Post http://localhost:8081/operator/revoke -ContentType 'application/json' `
  -Body (@{ username = 'alice'; reason = 'laptop reported stolen' } | ConvertTo-Json)
```

## Tests

Unit tests cover snapshot signing, the mode state machine, eligibility rules, revocation, recovery and the audit chain. They need the .NET 10 SDK and no running services.

```bash
dotnet test Mif.slnx
```

The end-to-end drill drives a real browser with a virtual passkey through the full story against the running stack, stopping and starting `fake-entra` itself.

```bash
cd e2e
npm install
npx playwright install chromium
npm run drill
```

## Layout

```
prototype/
├─ docker-compose.yml
├─ Dockerfile                 builds either .NET service
├─ keycloak/
│  ├─ mif-realm.json          broker realm: upstream IdP, both sign-in flows, clients
│  └─ upstream-realm.json     the stand-in for Entra, with test users
├─ src/
│  ├─ Mif.Node/               snapshot service, continuity controller, audit log
│  ├─ Mif.Client/             claim helpers and the "live identity" policy for ASP.NET Core apps
│  └─ Mif.DemoApp/            example application
├─ tests/Mif.Node.Tests/
└─ e2e/outage-drill.cjs
```

## Pointing it at a real Entra tenant

Not tested yet. The upstream is configured entirely through the `MIF_UPSTREAM_*` variables on the `keycloak` service and the `Mif__Upstream__*` variables on `mif-node`, so no code or realm changes should be needed:

| Variable | Entra value |
|---|---|
| `MIF_UPSTREAM_ISSUER` | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `MIF_UPSTREAM_AUTHORIZATION_URL` | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize` |
| `MIF_UPSTREAM_TOKEN_URL` | `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` |
| `MIF_UPSTREAM_JWKS_URL` | `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys` |
| `MIF_UPSTREAM_CLIENT_ID` / `_SECRET` | The broker app registration |
| `Mif__Upstream__DiscoveryUrl` | `https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration` |
| `Mif__Upstream__ProbeTokenUrl`, `ProbeClientId`, `ProbeClientSecret`, `ProbeScope` | A separate app registration with no permissions. Confirm in your tenant which scope it can request. |

The realm is imported only when it does not exist yet. After changing these values, recreate the stack with `docker compose down -v`.

## Not for deployment as is

- Keycloak runs in development mode over plain HTTP.
- Every secret in `docker-compose.yml` and the realm files is a throwaway value.
- The broker and the node share one database user.
- There is no standby node; see the profile for the intended Azure and on-prem layout.

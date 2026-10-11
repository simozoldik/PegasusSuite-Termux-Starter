# Pegasus Suite — architecture notes

## Runtime picture

```
Android app (Capacitor WebView, https://localhost)
  │  assets/public/{index.html,app.js,styles.css}   ← built from frontend/
  │  native plugins: PhoneScanner, WiFiCracker, CellTower
  │
  └── HTTP ──► backend (Node/Express, PC on the same Wi-Fi, :8710)
                 /api/lan/scan, /api/camera/audit, /api/location/triangulate, ...
```

The WIFI tab runs entirely on-device through the Capacitor plugins. RECON,
CAMERAS and PHONES need the backend because LAN/subnet probing cannot be done
from inside a WebView.

## Frontend (`frontend/`, mirrored into `www/` and `android/app/src/main/assets/public/`)

- `index.html` — four tab panels (RECON / CAMERAS / WIFI / PHONES). No login view,
  no identity fields.
- `app.js` — one IIFE. Builds URLs as `<apiBaseUrl>/api/<path>`, resolves the
  backend Base URL from `window.__PEGASUS_CONFIG__.apiBaseUrl` with a
  `localStorage` override (`pegasus_api_base`), and bridges to the native plugins
  through `window.Capacitor.Plugins[...]` with a per-call timeout and graceful
  fallback when a plugin is absent.
- `styles.css` — including the animated radar sweep drawn on the 1002×1002
  canvas (device-pixel-ratio aware).
- CSP-compatible: no inline scripts or styles; the backend sets the same policy
  via `helmet`.

Keep `frontend/`, `www/` and the Android asset copy in sync — `npm run build`
followed by `npx cap sync android` does that.

## Backend (`backend/`)

- `config.js` loads `.env` (no dependency) and exposes the effective settings.
  `validateStartup()` refuses to boot on unsafe combinations.
- `app.js` mounts the Pegasus API at `/api`, then serves `frontend/` as static
  files with an SPA fallback for non-`/api` paths.
- `routes/security.js` — the whole API surface, guarded by a rate limiter:
  `/lan/scan`, `/lan/subnets`, `/camera/audit`, `/camera/scan-plan`,
  `/camera/rtsp-urls`, `/location/triangulate`, `/phone/discover`,
  `/phone/audit`, `/phone/audit/:jobId`, `/phone/scan-plan`,
  `/wifi/parse-handshake`, `/wifi/crack-plan`, `/security/all`.
- `services/lanAudit.js` — derives the reachable subnets from `os.networkInterfaces()`
  and probes hosts/ports with bounded concurrency and short timeouts.
- `services/cameraHacker.js` — turns a CIDR into HTTP/RTSP candidate plans.
- `services/wifiCracker.js` — parses `.22000` handshakes and returns a planning
  object (commands, wordlist hints); it never executes a crack.
- `services/cellTriangulation.js` — Gauss-Newton weighted least squares over the
  supplied towers, degrading to `single_cell` / `unknown` when there are too few.

Every endpoint is deliberately side-effect free: it observes reachability or
returns a plan. Nothing is written to the targets.

## Migration notes

This project was migrated from an earlier internal web application that shared
the same repository. The active app, its assets and this backend API are
Pegasus-only: English UI, no login screen, no user identity and no business
workflow.

The earlier application's source (its `salesforce/` folder, `authService.js`,
its order/billing service modules, `routes/index.js`, `db.js`), its database
and its signed binaries have been removed from the working tree. The remaining
tree is a clean Pegasus layout:

```
backend/src/
├── app.js            # Express assembly + static frontend
├── config.js         # central configuration
├── server.js         # entry point
├── lib/              # errors, logger
├── middleware/       # cors, errorHandler
├── routes/security.js
└── services/         # lanAudit, phoneAudit, cameraHacker, wifiCracker, cellTriangulation
```

## Operational notes

- Backend must bind `0.0.0.0` so the phone can reach it: `HOST=0.0.0.0`, `PORT=8710`.
- Windows Firewall must allow inbound TCP 8710 on the private network.
- Android `network_security_config.xml` allows cleartext to the LAN backend for
  lab use — replace with HTTPS before any deployment outside the lab.
- The phone and the PC must be on the same subnet for RECON/CAMERAS.

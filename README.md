# Pegasus Suite

Android field-reconnaissance toolkit. One app, four tabs:

| Tab | What it does |
|---|---|
| **RECON** | Discovers live hosts on the local subnet(s) and reports open service ports. |
| **CAMERAS** | Finds camera-like HTTP/RTSP endpoints in a CIDR range and audits their exposure. |
| **WIFI** | Enumerates visible access points (SSID, BSSID, channel, signal, security). |
| **CELL** | Reads serving/neighbouring cell towers and estimates position by multilateration. |

English only. No login screen, no user identity, no account data.

> Use only against assets and networks you are explicitly authorised to test.

---

## Layout

```
pegasus-suite/
├── backend/                     # Node/Express API (also serves the web app)
│   ├── src/
│   │   ├── server.js            # entry point, fail-closed startup validation
│   │   ├── app.js               # Express assembly (helmet, CORS, routes, static)
│   │   ├── config.js            # central configuration (.env loader)
│   │   ├── routes/
│   │   │   └── security.js      # Pegasus Suite API surface
│   │   └── services/
│   │       ├── lanAudit.js          # subnet discovery + port probing
│   │       ├── cameraHacker.js      # CIDR -> RTSP/HTTP candidate plans
│   │       ├── wifiCracker.js       # .22000 handshake parsing + hashcat plan
│   │       └── cellTriangulation.js # Gauss-Newton weighted multilateration
│   └── .env                     # dev settings (HOST=0.0.0.0, PORT=8710)
├── frontend/                    # the web app served by the backend
│   ├── index.html
│   ├── app.js                   # tab logic, radar scan animation, native bridge
│   ├── styles.css
│   └── config.js                # apiBaseUrl used by the Android bundle
├── www/                         # Capacitor copy of the web app
├── android/                     # Capacitor Android project
│   └── app/src/main/
│       ├── java/com/pegasus/suite/
│       │   ├── MainActivity.java
│       │   ├── CellTowerPlugin.java
│       │   ├── PhoneScannerPlugin.java
│       │   └── WiFiCrackerPlugin.java
│       └── AndroidManifest.xml
├── scripts/                     # build helpers (build-web.js, keystore generation)
├── start-server.bat             # start the backend
└── build-apk.bat                # build the debug APK
```

---

## Quick start (PC)

```bat
:: 1) Start the backend
start-server.bat
:: then open http://localhost:8710/

:: 2) Optional: rebuild the web bundle + sync into the Android project
npm install
npm run build
npx cap sync android
```

## Building the Android app

```bat
build-apk.bat
:: equivalent to:
::   npm install
::   npx cap sync android
::   cd android && gradlew.bat assembleDebug
::   adb install -r app\build\outputs\apk\debug\Pegasus-Suite-debug.apk
```

### Pointing the phone at the backend

Edit `www/config.js` (and `frontend/config.js`) and set `apiBaseUrl` to the PC's
LAN address, e.g. `http://192.168.1.137:8710`. The backend must listen on
`HOST=0.0.0.0`. The value can also be changed at runtime from the in-app
**Connection & settings** panel (stored in `localStorage`).

---

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/lan/scan` | Discover live hosts + open ports for a CIDR (`{cidr}`) |
| GET  | `/api/lan/subnets` | Subnets reachable from the backend host |
| POST | `/api/camera/audit` | Audit camera-like endpoints in a CIDR |
| POST | `/api/camera/scan-plan` | Build an RTSP/HTTP probe plan for a CIDR |
| GET  | `/api/camera/rtsp-urls?host=` | Candidate RTSP URLs for one host |
| POST | `/api/location/triangulate` | Position estimate from `{towers:[...]}` |
| POST | `/api/phone/scan-plan` | Plan for enumerating nearby devices (`{cidr}`) |
| POST | `/api/wifi/parse-handshake` | Parse a `.22000` handshake |
| POST | `/api/wifi/crack-plan` | Produce a hashcat plan (planning only) |
| GET  | `/api/security/all` | Capability report for the whole suite |

`triangulate` returns `method` = `triangulation` / `single_cell` / `unknown` and
`confidence` = `high` / `medium` / `low` / `none`.

---

## Security notes

- All API endpoints are **read-only / planning** endpoints: they report what is
  reachable and produce plans. They do not crack anything themselves.
- The backend is a read-only observer: it probes reachability and returns
  plans/estimates. There is no authentication because there is no account, no
  login and no mutation endpoint — run it only on trusted lab networks.
- `network_security_config.xml` currently permits cleartext HTTP to the LAN
  backend. Replace it with HTTPS before any non-lab deployment.
- The backend must be reachable from the phone's Wi-Fi network for the CAMERAS /
  RECON tabs to work; the WIFI and CELL tabs work fully on-device.

See `docs/PEGASUS-SUITE.md` for the deeper architecture notes.

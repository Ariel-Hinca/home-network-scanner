# HomeGuard

HomeGuard is a local, defensive scanner for a home network you are allowed to test. Phase 1 can look for devices on a confirmed home network of `/24` or smaller. It does not run a full port scan or vulnerability checks.

The API is meant to listen on `127.0.0.1`. A target is stored only when it is an IPv4 network inside RFC 1918 and no larger than `/16`. The suggested scan size is `/24`.

## Layout

```text
homeguard/
  backend/          FastAPI, SQLAlchemy, scope policy, tests
  frontend/         React, TypeScript, Vite, Tailwind
  docs/             Structure, startup, and the health endpoint
```

See [docs/folder-structure.md](docs/folder-structure.md), [docs/startup.md](docs/startup.md), and [docs/health-endpoint.md](docs/health-endpoint.md).

## Run the backend

Install Python 3.12, then from `homeguard/backend`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m app
```

The service listens on `http://127.0.0.1:8000`. Interactive docs are at `http://127.0.0.1:8000/docs`.

## Run the frontend

From `homeguard/frontend`, with the API already running:

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. The dev server proxies `/api` to the backend.

## Test the API

From `homeguard/backend` with the virtualenv active:

```powershell
pytest
```

Against a running server:

```powershell
curl http://127.0.0.1:8000/api/health
curl -X POST http://127.0.0.1:8000/api/networks/validate -H "Content-Type: application/json" -H "X-HomeGuard-Request: 1" -d "{\"cidr\":\"8.8.8.8/32\"}"
curl -X POST http://127.0.0.1:8000/api/networks/validate -H "Content-Type: application/json" -H "X-HomeGuard-Request: 1" -d "{\"cidr\":\"192.168.1.0/24\"}"
```

A public address returns `400` with code `public_range`. `192.168.1.0/24` returns `200`. Mutating requests without `X-HomeGuard-Request: 1` return `403`.

## Check phase 1

Install Nmap from [nmap.org](https://nmap.org/download.html) and reopen the terminal so `nmap` is on PATH. Start the backend, then in a second terminal:

```powershell
cd C:\Users\hinca\OneDrive\Bureaublad\CURSOR\home-network-scanner\homeguard\backend
.\.venv\Scripts\Activate.ps1
pytest
curl http://127.0.0.1:8000/api/health
```

`pytest` should pass. Health should show `"nmap": "ok"` and `"scan_scope": "/24"`. If `nmap` is `missing`, install Nmap and start the backend again.

Then open `http://127.0.0.1:5173`, create or sign in with the passphrase, save your suggested `/24`, click **Confirm this network**, and on the dashboard click **Look for devices**. The status should move to `running`, then `completed`, with a list of devices that answered. A second click while it is running should be refused. **Cancel** should stop it.

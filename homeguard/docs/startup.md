# Startup

Phase 0 expects two processes on the same machine. Nothing listens on a public interface when you use the commands below.

## Backend

Requirements: Python 3.12.

```powershell
cd homeguard\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python -m app
```

`python -m app` reads `HOMEGUARD_API_HOST` and `HOMEGUARD_API_PORT`. The default host is `127.0.0.1` and the default port is `8000`. A host other than `127.0.0.1`, `::1`, or `localhost` is rejected when settings load.

On startup the app:

1. Loads settings from the environment and `backend/.env`.
2. Resolves the SQLite path. A relative URL such as `sqlite:///./data/homeguard.db` is placed under `backend/`.
3. Creates the data directory and tables.
4. Enables SQLite foreign keys and WAL mode.

Equivalent explicit command:

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Run that from `homeguard/backend` so `app` is on the import path.

## Frontend

Requirements: Node.js 22 or newer.

```powershell
cd homeguard\frontend
npm install
npm run dev
```

Vite serves `http://127.0.0.1:5173` and proxies `/api` to `http://127.0.0.1:8000`. Start the API first. The dashboard reads `/api/health`. The setup page reads interfaces and can store a suggested `/24` after you create a passphrase.

## Tests

From `homeguard/backend`, with the virtualenv active:

```powershell
pytest
```

The tests use a temporary SQLite file. They do not touch `backend/data/homeguard.db`.

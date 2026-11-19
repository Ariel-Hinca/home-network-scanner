# Folder structure

```text
homeguard/
  README.md
  .gitignore
  docs/
    folder-structure.md
    startup.md
    health-endpoint.md
  backend/
    requirements.txt
    .env.example
    pytest.ini
    data/                      SQLite file is created here and gitignored
    app/
      __main__.py              `python -m app` binds the loopback host
      main.py                  FastAPI factory, CORS, lifespan, /api mount
      config.py                Pydantic settings, HOMEGUARD_* variables
      database.py              SQLite engine, WAL, create_all
      models.py                settings, sessions, networks, scans, devices, audit events
      schemas.py               request and response models
      api/
        deps.py                DB session, local header, cookie session
        router.py              mounts the route modules
        routes/
          health.py            GET /api/health
          setup.py             passphrase and session
          networks.py          scope check, interfaces, saved networks
          profiles.py          GET /api/profiles
          scans.py             device search and common-port check
          audit.py             recent local events
      domain/
        policy.py              RFC 1918, /16 save cap, /24 discovery cap
        interfaces.py          local IPv4 adapters
        passwords.py           Argon2id hashing
      adapters/nmap/           fixed Nmap arguments and XML reading
      workers/scan_worker.py   one discovery at a time
    tests/
  frontend/
    package.json
    .env.example
    index.html
    vite.config.ts
    src/
      main.tsx
      App.tsx                  routes
      api.ts                   fetch client
      components/Layout.tsx
      pages/Dashboard.tsx
      pages/Setup.tsx
```

`domain/` does not import FastAPI. HTTP code calls the policy, then stores the normalized CIDR. The frontend talks to `/api` and, in development, Vite forwards that prefix to port 8000.

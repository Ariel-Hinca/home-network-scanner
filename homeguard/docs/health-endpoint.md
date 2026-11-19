# Health endpoint

`GET /api/health` reports whether this process can use its database, and which scope rules it is enforcing. It does not scan the network and it does not require a session or the local request header, so a browser or `curl` can call it directly.

```powershell
curl http://127.0.0.1:8000/api/health
```

Example response (`200`):

```json
{
  "status": "ok",
  "service": "HomeGuard",
  "version": "0.1.0",
  "database": "ok",
  "nmap": "ok",
  "api_host": "127.0.0.1",
  "api_port": 8000,
  "scope_policy": {
    "address_family": "ipv4",
    "allowed_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "max_scope": "/16",
    "default_scope": "/24",
    "scan_scope": "/24"
  }
}
```

What each field means:

- `status` is `ok` when `SELECT 1` succeeds. It is `degraded` when the database check fails, and the HTTP status is then `503`.
- `database` is `ok` or `error` for that same check.
- `nmap` is `ok` when the Nmap program can be found, and `missing` when it cannot. A missing Nmap install does not by itself make `status` degraded.
- `scan_scope` is the largest network discovery will run. `/24` means a normal home-sized range.
- `api_host` and `api_port` are the configured bind, not a measurement of who is connected.
- `scope_policy.allowed_ranges` lists the three RFC 1918 blocks. A target must sit entirely inside one of them.
- `max_scope` is `/16`. A prefix length below 16, such as `10.0.0.0/8`, is rejected as too large.
- `default_scope` is `/24`. Interface discovery suggests a `/24` around each private address.

The dashboard calls this endpoint on load and shows those fields. Scope decisions for a specific CIDR go through `POST /api/networks/validate`, which uses the same rules and returns `400` when a target is public, too large, or not IPv4.

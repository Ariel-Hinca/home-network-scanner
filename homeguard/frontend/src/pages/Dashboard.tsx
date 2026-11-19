import { FormEvent, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { DiscoveredHost, Health, Network, Scan, SetupStatus, ValidatedCidr } from "../types";

export function DashboardPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [cidr, setCidr] = useState("192.168.1.0/24");
  const [result, setResult] = useState<ValidatedCidr | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [scan, setScan] = useState<Scan | null>(null);
  const [hosts, setHosts] = useState<DiscoveredHost[]>([]);
  const [scanError, setScanError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    api<Health>("/api/health")
      .then((body) => {
        if (active) {
          setHealth(body);
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setHealthError(error instanceof Error ? error.message : "The API did not respond.");
        }
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const [nextStatus, nextNetworks] = await Promise.all([
          api<SetupStatus>("/api/setup"),
          api<Network[]>("/api/networks"),
        ]);
        if (!active) {
          return;
        }
        setStatus(nextStatus);
        setNetworks(nextNetworks);
        const scans = nextStatus.authenticated ? await api<Scan[]>("/api/scans") : [];
        const latest = scans[0] ?? null;
        setScan(latest);
        if (latest && (latest.status === "completed" || latest.status === "cancelled")) {
          setHosts(await api<DiscoveredHost[]>(`/api/scans/${latest.id}/hosts`));
        }
      } catch (error) {
        if (active && error instanceof ApiError && error.status !== 401) {
          setScanError(error.message);
        }
      }
    }
    load();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!scan || (scan.status !== "queued" && scan.status !== "running")) {
      return;
    }
    const timer = window.setInterval(() => {
      api<Scan>(`/api/scans/${scan.id}`)
        .then(async (next) => {
          setScan(next);
          if (next.status === "completed" || next.status === "cancelled" || next.status === "failed") {
            setHosts(await api<DiscoveredHost[]>(`/api/scans/${next.id}/hosts`));
            setBusy(false);
          }
        })
        .catch((error: unknown) => {
          setScanError(error instanceof ApiError ? error.message : "The discovery status could not be read.");
        });
    }, 1500);
    return () => window.clearInterval(timer);
  }, [scan]);

  async function onCheck(event: FormEvent) {
    event.preventDefault();
    setChecking(true);
    setResult(null);
    setCheckError(null);
    try {
      const body = await api<ValidatedCidr>("/api/networks/validate", {
        method: "POST",
        body: JSON.stringify({ cidr }),
      });
      setResult(body);
    } catch (error) {
      setCheckError(error instanceof ApiError ? error.message : "The check failed.");
    } finally {
      setChecking(false);
    }
  }

  async function startDiscovery(network: Network) {
    setBusy(true);
    setScanError(null);
    setHosts([]);
    try {
      const started = await api<Scan>("/api/scans", {
        method: "POST",
        body: JSON.stringify({ network_id: network.id, profile: "discovery" }),
      });
      setScan(started);
    } catch (error) {
      setScanError(error instanceof ApiError ? error.message : "Discovery did not start.");
      setBusy(false);
    }
  }

  async function cancelDiscovery() {
    if (!scan) {
      return;
    }
    setScanError(null);
    try {
      setScan(await api<Scan>(`/api/scans/${scan.id}/cancel`, { method: "POST" }));
    } catch (error) {
      setScanError(error instanceof ApiError ? error.message : "Discovery could not be cancelled.");
    }
  }

  const running = scan?.status === "queued" || scan?.status === "running";

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-medium">Dashboard</h1>
        <p className="mt-2 max-w-2xl text-sm text-stone-600">
          Phase 1 looks for devices on a confirmed home network. It does not check open ports
          beyond a short list of common ones, and it does not look for vulnerabilities.
        </p>
      </section>

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <h2 className="text-base font-medium">Service</h2>
        {healthError && <p className="mt-3 text-sm text-red-800">{healthError}</p>}
        {!health && !healthError && <p className="mt-3 text-sm text-stone-600">Checking the API…</p>}
        {health && (
          <dl className="mt-4 grid gap-4 sm:grid-cols-3">
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Status</dt>
              <dd className="mt-1 text-sm">{health.status}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Database</dt>
              <dd className="mt-1 text-sm">{health.database}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Nmap</dt>
              <dd className="mt-1 text-sm">{health.nmap === "ok" ? "ready" : "not found"}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Bind</dt>
              <dd className="mt-1 text-sm">
                {health.api_host}:{health.api_port}
              </dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="text-xs uppercase tracking-wide text-stone-500">Allowed ranges</dt>
              <dd className="mt-1 text-sm">{health.scope_policy.allowed_ranges.join(", ")}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Largest saved scope</dt>
              <dd className="mt-1 text-sm">{health.scope_policy.max_scope}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Discovery size</dt>
              <dd className="mt-1 text-sm">{health.scope_policy.scan_scope} or smaller</dd>
            </div>
          </dl>
        )}
      </section>

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <h2 className="text-base font-medium">Find devices</h2>
        {status && !status.authenticated && (
          <p className="mt-3 text-sm text-stone-600">Sign in on the Setup page before starting a discovery.</p>
        )}
        {health?.nmap === "missing" && (
          <p className="mt-3 text-sm text-red-800">
            Nmap was not found. Install Nmap, reopen the terminal, and start the backend again.
          </p>
        )}
        {networks.length === 0 && (
          <p className="mt-3 text-sm text-stone-600">Save a home network on the Setup page first.</p>
        )}
        <ul className="mt-4 space-y-3">
          {networks.map((network) => (
            <li key={network.id} className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <span className="text-sm">
                {network.name} · {network.cidr}
                {network.ownership_confirmed ? " · confirmed" : " · not confirmed"}
              </span>
              <button
                className="w-fit rounded-md bg-stone-900 px-3 py-1.5 text-sm text-stone-50 disabled:opacity-50"
                type="button"
                disabled={!status?.authenticated || !network.ownership_confirmed || running || busy}
                onClick={() => startDiscovery(network)}
              >
                Look for devices
              </button>
            </li>
          ))}
        </ul>
        {scan && (
          <p className="mt-4 text-sm text-stone-800">
            Latest discovery is {scan.status}
            {scan.status === "completed" ? ` · ${scan.host_count} device(s)` : ""}
            {scan.error ? ` · ${scan.error}` : ""}
          </p>
        )}
        {running && (
          <button
            className="mt-3 rounded-md border border-stone-400 px-3 py-1.5 text-sm"
            type="button"
            onClick={cancelDiscovery}
          >
            Cancel
          </button>
        )}
        {scanError && <p className="mt-3 text-sm text-red-800">{scanError}</p>}
        {scan?.status === "completed" && hosts.length === 0 && (
          <p className="mt-4 text-sm text-stone-600">
            No devices answered. They may be off, or they may not use the common ports this check tries.
          </p>
        )}
        {hosts.length > 0 && (
          <ul className="mt-4 divide-y divide-stone-200">
            {hosts.map((host) => (
              <li key={host.ip} className="py-2 text-sm">
                {host.ip}
                {host.hostname ? ` · ${host.hostname}` : ""}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <h2 className="text-base font-medium">Check a target</h2>
        <form className="mt-4 flex flex-col gap-3 sm:flex-row" onSubmit={onCheck}>
          <label className="flex-1 text-sm">
            <span className="mb-1 block text-stone-600">IPv4 CIDR</span>
            <input
              className="w-full rounded-md border border-stone-300 px-3 py-2"
              value={cidr}
              onChange={(event) => setCidr(event.target.value)}
              spellCheck={false}
              required
            />
          </label>
          <button
            className="self-end rounded-md bg-stone-900 px-4 py-2 text-sm text-stone-50 disabled:opacity-60"
            type="submit"
            disabled={checking}
          >
            {checking ? "Checking…" : "Check"}
          </button>
        </form>
        {result && (
          <p className="mt-4 text-sm text-stone-800">
            {result.cidr} is inside an RFC 1918 range and within {result.max_scope}. It contains{" "}
            {result.num_addresses} addresses.
            {result.host_bits_normalized ? " Host bits were normalized to the network address." : ""}
          </p>
        )}
        {checkError && <p className="mt-4 text-sm text-red-800">{checkError}</p>}
      </section>
    </div>
  );
}

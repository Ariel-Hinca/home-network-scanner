import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
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
  const [scans, setScans] = useState<Scan[]>([]);
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
      .catch(() => {
        if (active) {
          setHealthError("HomeGuard is not running. Start it, then refresh this page.");
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
        const nextScans = nextStatus.authenticated ? await api<Scan[]>("/api/scans") : [];
        const latest = nextScans[0] ?? null;
        setScans(nextScans);
        setScan(latest);
        if (latest && (latest.status === "completed" || latest.status === "cancelled")) {
          setHosts(await api<DiscoveredHost[]>(`/api/scans/${latest.id}/hosts`));
        }
      } catch (error) {
        if (active && error instanceof ApiError && error.status !== 401) {
          setScanError("HomeGuard could not load your last search.");
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
        .catch(() => {
          setScanError("HomeGuard could not update the search. Refresh the page.");
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
      setCheckError(
        error instanceof ApiError
          ? "HomeGuard cannot check that network. Use a private home address such as 192.168.1.0/24."
          : "The check failed.",
      );
    } finally {
      setChecking(false);
    }
  }

  async function startScan(network: Network, profile: "discovery" | "common_tcp") {
    setBusy(true);
    setScanError(null);
    setHosts([]);
    try {
      const started = await api<Scan>("/api/scans", {
        method: "POST",
        body: JSON.stringify({ network_id: network.id, profile }),
      });
      setScan(started);
      setScans((current) => [started, ...current]);
    } catch (error) {
      setScanError(plainScanError(error));
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
    } catch {
      setScanError("The search could not be stopped.");
    }
  }

  const running = scan?.status === "queued" || scan?.status === "running";
  const canCheckPorts = scans.some(
    (item) => item.profile === "discovery" && item.status === "completed" && item.host_count > 0,
  );
  const ready = health?.status === "ok" && health.database === "ok" && health.nmap === "ok";

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-medium">Your home network</h1>
        <p className="mt-2 max-w-2xl text-sm text-stone-600">
          HomeGuard looks for phones, computers, printers, and the router on the Wi-Fi you allowed.
          It can then check a fixed list of common ports on those devices. It does not look for viruses yet.
        </p>
      </section>

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <h2 className="text-base font-medium">{ready ? "HomeGuard is ready" : "HomeGuard is not ready"}</h2>
        {healthError && <p className="mt-3 text-sm text-red-800">{healthError}</p>}
        {!health && !healthError && <p className="mt-3 text-sm text-stone-600">Checking that HomeGuard is running…</p>}
        {health?.nmap === "missing" && (
          <p className="mt-3 text-sm text-red-800">
            The program that looks for devices is missing. Install Nmap, close and reopen the terminal, then start HomeGuard again.
          </p>
        )}
        {health && health.nmap === "ok" && health.status === "ok" && (
          <p className="mt-3 text-sm text-stone-600">You can look for devices on a home network you have allowed.</p>
        )}
        {health && (
          <details className="mt-4 text-sm text-stone-600">
            <summary className="cursor-pointer">Technical details</summary>
            <dl className="mt-3 grid gap-3 sm:grid-cols-2">
              <div>
                <dt>App</dt>
                <dd>{health.status === "ok" ? "Running" : "Having trouble"}</dd>
              </div>
              <div>
                <dt>Saved information</dt>
                <dd>{health.database === "ok" ? "Available" : "Unavailable"}</dd>
              </div>
              <div>
                <dt>Device search</dt>
                <dd>{health.nmap === "ok" ? "Available" : "Missing"}</dd>
              </div>
              <div>
                <dt>This computer only</dt>
                <dd>
                  {health.api_host}:{health.api_port}
                </dd>
              </div>
            </dl>
          </details>
        )}
      </section>

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <h2 className="text-base font-medium">Devices on your Wi-Fi</h2>
        {status && !status.authenticated && (
          <p className="mt-3 text-sm text-stone-600">
            <Link className="underline" to="/setup">Sign in on the Setup page</Link> before looking for devices.
          </p>
        )}
        {status?.authenticated && networks.length === 0 && (
          <p className="mt-3 text-sm text-stone-600">
            <Link className="underline" to="/setup">Choose your home Wi-Fi on the Setup page</Link> first.
          </p>
        )}
        {status?.authenticated && networks.some((network) => !network.ownership_confirmed) && (
          <p className="mt-3 text-sm text-stone-600">
            A saved network is still waiting. On the Setup page, click “This is my home network.”
          </p>
        )}
        <ul className="mt-4 space-y-3">
          {networks.map((network) => (
            <li key={network.id} className="flex flex-col items-start gap-2 border-t border-stone-200 pt-3 first:border-t-0 first:pt-0">
              <span className="text-sm">
                <span className="font-medium">{friendlyName(network.name)}</span>
                <span className="mt-1 block text-stone-600">
                  {network.cidr}
                  {network.ownership_confirmed ? " · Allowed" : " · Not allowed yet"}
                </span>
              </span>
              <div className="flex flex-wrap gap-2">
                <button
                  className="w-fit rounded-md bg-stone-900 px-3 py-1.5 text-sm text-stone-50 disabled:opacity-50"
                  type="button"
                  disabled={!status?.authenticated || !network.ownership_confirmed || running || busy || health?.nmap === "missing"}
                  onClick={() => startScan(network, "discovery")}
                >
                  {running && scan?.profile === "discovery" ? "Looking…" : "Look for devices"}
                </button>
                <button
                  className="w-fit rounded-md border border-stone-400 px-3 py-1.5 text-sm disabled:opacity-50"
                  type="button"
                  disabled={!status?.authenticated || !network.ownership_confirmed || !canCheckPorts || running || busy || health?.nmap === "missing"}
                  onClick={() => startScan(network, "common_tcp")}
                >
                  {running && scan?.profile === "common_tcp" ? "Checking…" : "Check common ports"}
                </button>
              </div>
            </li>
          ))}
        </ul>
        {scan && <p className="mt-4 text-sm text-stone-800">{searchSummary(scan)}</p>}
        {running && (
          <button
            className="mt-3 rounded-md border border-stone-400 px-3 py-1.5 text-sm"
            type="button"
            onClick={cancelDiscovery}
          >
            Stop
          </button>
        )}
        {scanError && <p className="mt-3 text-sm text-red-800">{scanError}</p>}
        {scan?.status === "completed" && hosts.length === 0 && (
          <p className="mt-4 text-sm text-stone-600">
            No devices answered. They may be turned off, asleep, or not answering this kind of check.
          </p>
        )}
        {hosts.length > 0 && (
          <div className="mt-4">
            <h3 className="text-sm font-medium">Devices that answered</h3>
            <ul className="mt-2 divide-y divide-stone-200">
              {hosts.map((host) => (
                <li key={host.ip} className="py-2 text-sm">
                  <span className="font-medium">{host.hostname || "Unnamed device"}</span>
                  <span className="mt-1 block text-stone-600">Address {host.ip}</span>
                  <PortSummary services={host.services ?? []} />
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <details className="rounded-lg border border-stone-300 bg-white p-5 text-sm">
        <summary className="cursor-pointer text-base font-medium">Check an address before saving it</summary>
        <p className="mt-3 text-stone-600">
          Use this only if you want to know whether an address is a private home network. An example is 192.168.1.0/24.
        </p>
        <form className="mt-4 flex flex-col gap-3 sm:flex-row" onSubmit={onCheck}>
          <label className="flex-1">
            <span className="mb-1 block text-stone-600">Network address</span>
            <input
              className="w-full rounded-md border border-stone-300 px-3 py-2"
              value={cidr}
              onChange={(event) => setCidr(event.target.value)}
              spellCheck={false}
              required
            />
          </label>
          <button
            className="self-end rounded-md bg-stone-900 px-4 py-2 text-stone-50 disabled:opacity-60"
            type="submit"
            disabled={checking}
          >
            {checking ? "Checking…" : "Check"}
          </button>
        </form>
        {result && (
          <p className="mt-4 text-stone-800">
            Yes. {result.cidr} is a private home network. It covers about {result.num_addresses} addresses.
            {result.host_bits_normalized ? " The address was adjusted to the start of that network." : ""}
          </p>
        )}
        {checkError && <p className="mt-4 text-red-800">{checkError}</p>}
      </details>
    </div>
  );
}

function friendlyName(name: string) {
  if (name === "WiFi" || name === "Wi-Fi" || name === "WLAN") {
    return "Wi-Fi";
  }
  if (name === "Ethernet") {
    return "Ethernet cable";
  }
  return name;
}

function PortSummary({ services }: { services: { port: number; state: string }[] }) {
  if (services.length === 0) {
    return null;
  }
  const open = services.filter((service) => service.state === "open").map((service) => service.port);
  const closed = services.filter((service) => service.state !== "open").length;
  return (
    <span className="mt-1 block text-stone-600">
      {open.length > 0 ? `Open ports: ${open.join(", ")}.` : "No common ports were open."}
      {closed > 0 ? ` ${closed} other checked ports were closed or did not answer.` : ""}
    </span>
  );
}

function searchSummary(scan: Scan) {
  const ports = scan.profile === "common_tcp";
  if (scan.status === "queued" || scan.status === "running") {
    return ports
      ? "Checking common ports on the devices already found. This can take longer than finding devices. Leave this page open."
      : "Looking for devices. This can take a few minutes. Leave this page open.";
  }
  if (scan.status === "completed") {
    const count = scan.host_count;
    if (ports) {
      const label = count === 1 ? "1 device was checked." : `${count} devices were checked.`;
      return `Finished. ${label} Open ports are listed under each device.`;
    }
    const label = count === 1 ? "1 device answered." : `${count} devices answered.`;
    return `Finished. ${label}`;
  }
  if (scan.status === "cancelled") {
    return "Stopped. The list may be incomplete.";
  }
  if (scan.status === "failed") {
    return scan.error ? `The search did not finish. ${scan.error}` : "The search did not finish.";
  }
  return "No search yet.";
}

function plainScanError(error: unknown) {
  if (!(error instanceof ApiError)) {
    return "The search did not start.";
  }
  if (error.code === "ownership_required") {
    return "Allow this network on the Setup page before looking for devices.";
  }
  if (error.code === "scan_in_progress") {
    return "A search is already running. Wait for it to finish, or stop it.";
  }
  if (error.code === "no_devices") {
    return "Look for devices first. The port check only runs on devices that already answered.";
  }
  if (error.code === "scan_scope_too_large") {
    return "That network is too big to search in one go. Choose a normal home network on the Setup page.";
  }
  if (error.code === "nmap_missing" || error.message.toLowerCase().includes("nmap")) {
    return "The program that looks for devices is missing. Install Nmap, then start HomeGuard again.";
  }
  return error.message || "The search did not start.";
}

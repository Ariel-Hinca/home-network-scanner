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
    <div className="space-y-6">
      <section className="overflow-hidden rounded-3xl bg-teal-800 px-6 py-7 text-teal-50 shadow-lg shadow-teal-900/10">
        <p className="text-xs font-semibold uppercase tracking-[0.16em] text-teal-200">Home</p>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight">Your home network</h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-teal-100">
          HomeGuard looks for phones, computers, printers, and the router on the Wi-Fi you allowed.
          It shows a name when the device or your router shares one, and otherwise the company on the network card.
          It can then check a fixed list of common ports and explain what an open port usually means.
          It does not look for viruses.
        </p>
      </section>

      <section className="rounded-3xl border border-white/80 bg-white/90 p-5 shadow-sm">
        <div className="flex items-center gap-3">
          <span className={`h-3 w-3 rounded-full ${ready ? "bg-emerald-500" : "animate-pulse bg-amber-400"}`} />
          <h2 className="text-base font-semibold">{ready ? "HomeGuard is ready" : "HomeGuard is not ready"}</h2>
        </div>
        {healthError && <p className="mt-3 rounded-2xl bg-rose-50 px-3 py-2 text-sm text-rose-800">{healthError}</p>}
        {!health && !healthError && <p className="mt-3 text-sm text-stone-600">Checking that HomeGuard is running…</p>}
        {health?.nmap === "missing" && (
          <p className="mt-3 rounded-2xl bg-rose-50 px-3 py-2 text-sm text-rose-800">
            The program that looks for devices is missing. Install Nmap, close and reopen the terminal, then start HomeGuard again.
          </p>
        )}
        {health && health.nmap === "ok" && health.status === "ok" && (
          <p className="mt-3 text-sm text-stone-600">You can look for devices on a home network you have allowed.</p>
        )}
        {health && (
          <details className="mt-4 text-sm text-stone-600">
            <summary className="cursor-pointer font-medium text-stone-700">Technical details</summary>
            <dl className="mt-3 grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl bg-stone-50 px-3 py-2">
                <dt className="text-xs uppercase tracking-wide text-stone-500">App</dt>
                <dd className="mt-1 font-medium text-stone-800">{health.status === "ok" ? "Running" : "Having trouble"}</dd>
              </div>
              <div className="rounded-2xl bg-stone-50 px-3 py-2">
                <dt className="text-xs uppercase tracking-wide text-stone-500">Saved information</dt>
                <dd className="mt-1 font-medium text-stone-800">{health.database === "ok" ? "Available" : "Unavailable"}</dd>
              </div>
              <div className="rounded-2xl bg-stone-50 px-3 py-2">
                <dt className="text-xs uppercase tracking-wide text-stone-500">Device search</dt>
                <dd className="mt-1 font-medium text-stone-800">{health.nmap === "ok" ? "Available" : "Missing"}</dd>
              </div>
              <div className="rounded-2xl bg-stone-50 px-3 py-2">
                <dt className="text-xs uppercase tracking-wide text-stone-500">This computer only</dt>
                <dd className="mt-1 font-medium text-stone-800">
                  {health.api_host}:{health.api_port}
                </dd>
              </div>
            </dl>
          </details>
        )}
      </section>

      <section className="rounded-3xl border border-white/80 bg-white/90 p-5 shadow-sm">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <h2 className="text-base font-semibold">Devices on your Wi-Fi</h2>
          {hosts.length > 0 && (
            <span className="rounded-full bg-teal-50 px-3 py-1 text-sm font-medium text-teal-900">
              {hosts.length === 1 ? "1 device" : `${hosts.length} devices`}
            </span>
          )}
        </div>
        {status && !status.authenticated && (
          <p className="mt-3 rounded-2xl bg-amber-50 px-3 py-2 text-sm text-amber-950">
            <Link className="font-medium underline" to="/setup">Sign in on the Setup page</Link> before looking for devices.
          </p>
        )}
        {status?.authenticated && networks.length === 0 && (
          <p className="mt-3 rounded-2xl bg-amber-50 px-3 py-2 text-sm text-amber-950">
            <Link className="font-medium underline" to="/setup">Choose your home Wi-Fi on the Setup page</Link> first.
          </p>
        )}
        {status?.authenticated && networks.some((network) => !network.ownership_confirmed) && (
          <p className="mt-3 rounded-2xl bg-amber-50 px-3 py-2 text-sm text-amber-950">
            A saved network is still waiting. On the Setup page, click “This is my home network.”
          </p>
        )}
        <ul className="mt-4 space-y-3">
          {networks.map((network) => (
            <li key={network.id} className="rounded-2xl bg-stone-50 px-4 py-3">
              <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-sm">
                  <span className="font-semibold">{friendlyName(network.name)}</span>
                  <span className="mt-1 flex flex-wrap items-center gap-2 text-stone-600">
                    <span>{network.cidr}</span>
                    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${network.ownership_confirmed ? "bg-emerald-100 text-emerald-900" : "bg-amber-100 text-amber-950"}`}>
                      {network.ownership_confirmed ? "Allowed" : "Not allowed yet"}
                    </span>
                  </span>
                </span>
                <div className="flex flex-wrap gap-2">
                  <button
                    className="w-fit rounded-full bg-teal-800 px-4 py-2 text-sm font-medium text-white shadow-sm disabled:opacity-50"
                    type="button"
                    disabled={!status?.authenticated || !network.ownership_confirmed || running || busy || health?.nmap === "missing"}
                    onClick={() => startScan(network, "discovery")}
                  >
                    {running && scan?.profile === "discovery" ? "Looking…" : "Look for devices"}
                  </button>
                  <button
                    className="w-fit rounded-full border border-teal-800/20 bg-white px-4 py-2 text-sm font-medium text-teal-900 disabled:opacity-50"
                    type="button"
                    disabled={!status?.authenticated || !network.ownership_confirmed || !canCheckPorts || running || busy || health?.nmap === "missing"}
                    onClick={() => startScan(network, "common_tcp")}
                  >
                    {running && scan?.profile === "common_tcp" ? "Checking…" : "Check common ports"}
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
        {scan && (
          <p className={`mt-4 rounded-2xl px-3 py-2 text-sm ${statusTone(scan)}`}>
            {running && <span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-current" />}
            {searchSummary(scan)}
          </p>
        )}
        {running && (
          <button
            className="mt-3 rounded-full border border-stone-300 bg-white px-4 py-2 text-sm font-medium"
            type="button"
            onClick={cancelDiscovery}
          >
            Stop
          </button>
        )}
        {scanError && <p className="mt-3 rounded-2xl bg-rose-50 px-3 py-2 text-sm text-rose-800">{scanError}</p>}
        {scan?.status === "completed" && hosts.length === 0 && (
          <p className="mt-4 rounded-2xl bg-stone-50 px-3 py-2 text-sm text-stone-600">
            No devices answered. They may be turned off, asleep, or not answering this kind of check.
          </p>
        )}
        {hosts.length > 0 && (
          <div className="mt-5">
            <h3 className="text-sm font-semibold">Devices that answered</h3>
            <p className="mt-1 text-sm leading-6 text-stone-600">
              A shared name is shown when one was found. Otherwise you see the company printed on the network card.
              After a port check, each open port has a short note: expected, worth a look, or close it if you do not use it.
            </p>
            <ul className="mt-3 grid gap-3">
              {hosts.map((host) => (
                <li key={host.ip} className="rounded-2xl border border-stone-200 bg-white p-4 text-sm shadow-sm">
                  <div className="flex items-start gap-3">
                    <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-2xl text-sm font-semibold ${markTone(host.kind)}`}>
                      {deviceMark(deviceTitle(host))}
                    </span>
                    <div className="min-w-0 flex-1">
                      <span className="font-semibold text-stone-900">{deviceTitle(host)}</span>
                      <span className="mt-1 block text-stone-600">Address {host.ip}</span>
                      {deviceNotes(host).map((note) => (
                        <span key={note} className="mt-1 block text-stone-600">
                          {note}
                        </span>
                      ))}
                      <PortSummary services={host.services ?? []} />
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <details className="rounded-3xl border border-white/80 bg-white/90 p-5 text-sm shadow-sm">
        <summary className="cursor-pointer text-base font-semibold">Check an address before saving it</summary>
        <p className="mt-3 text-stone-600">
          Use this only if you want to know whether an address is a private home network. An example is 192.168.1.0/24.
        </p>
        <form className="mt-4 flex flex-col gap-3 sm:flex-row" onSubmit={onCheck}>
          <label className="flex-1">
            <span className="mb-1 block text-stone-600">Network address</span>
            <input
              className="w-full rounded-2xl border border-stone-200 bg-stone-50 px-3 py-2 outline-none focus:border-teal-700 focus:bg-white"
              value={cidr}
              onChange={(event) => setCidr(event.target.value)}
              spellCheck={false}
              required
            />
          </label>
          <button
            className="self-end rounded-full bg-teal-800 px-5 py-2 font-medium text-white disabled:opacity-60"
            type="submit"
            disabled={checking}
          >
            {checking ? "Checking…" : "Check"}
          </button>
        </form>
        {result && (
          <p className="mt-4 rounded-2xl bg-emerald-50 px-3 py-2 text-emerald-950">
            Yes. {result.cidr} is a private home network. It covers about {result.num_addresses} addresses.
            {result.host_bits_normalized ? " The address was adjusted to the start of that network." : ""}
          </p>
        )}
        {checkError && <p className="mt-4 rounded-2xl bg-rose-50 px-3 py-2 text-rose-800">{checkError}</p>}
      </details>
    </div>
  );
}

function deviceMark(title: string) {
  const letter = title.replace(/[^A-Za-z0-9]/g, "").slice(0, 1).toUpperCase();
  return letter || "?";
}

function markTone(kind: string) {
  switch (kind) {
    case "router":
      return "bg-teal-100 text-teal-900";
    case "camera":
      return "bg-sky-100 text-sky-900";
    case "printer":
      return "bg-violet-100 text-violet-900";
    case "tv":
      return "bg-indigo-100 text-indigo-900";
    case "computer":
      return "bg-stone-200 text-stone-800";
    case "apple":
      return "bg-zinc-200 text-zinc-900";
    default:
      return "bg-amber-100 text-amber-950";
  }
}

function statusTone(scan: Scan) {
  if (scan.status === "queued" || scan.status === "running") {
    return "bg-teal-50 text-teal-950";
  }
  if (scan.status === "failed") {
    return "bg-rose-50 text-rose-900";
  }
  if (scan.status === "cancelled") {
    return "bg-amber-50 text-amber-950";
  }
  return "bg-emerald-50 text-emerald-950";
}

function deviceTitle(host: DiscoveredHost) {
  if (host.hostname) {
    return host.hostname;
  }
  const noun = kindNoun(host.kind);
  if (host.vendor) {
    if (!noun || host.vendor.toLowerCase().includes(noun.toLowerCase())) {
      return host.vendor;
    }
    if (host.kind === "apple" && /apple/i.test(host.vendor)) {
      return host.vendor;
    }
    return `${host.vendor} ${noun}`;
  }
  if (host.kind === "router") {
    return "Home router";
  }
  if (noun) {
    return noun.charAt(0).toUpperCase() + noun.slice(1);
  }
  return "Unnamed device";
}

function deviceNotes(host: DiscoveredHost) {
  const notes: string[] = [];
  if (host.vendor && host.hostname) {
    notes.push(`Maker ${host.vendor}`);
  }
  if (!host.hostname && host.vendor) {
    notes.push("This name is the company on the network card.");
  }
  if (host.mac) {
    notes.push(`Network card ${host.mac}`);
  }
  if (host.hostname && host.kind) {
    notes.push(kindNote(host.kind));
  }
  if (!host.hostname && !host.vendor && !host.kind) {
    notes.push("This device did not share a name.");
  }
  return notes;
}

function kindNoun(kind: string) {
  switch (kind) {
    case "router":
      return "router";
    case "camera":
      return "camera";
    case "printer":
      return "printer";
    case "tv":
      return "television";
    case "computer":
      return "computer";
    case "apple":
      return "Apple device";
    default:
      return "";
  }
}

function kindNote(kind: string) {
  switch (kind) {
    case "router":
      return "This address is usually the home router.";
    case "camera":
      return "The open ports are common for a camera.";
    case "printer":
      return "The open ports are common for a printer.";
    case "tv":
      return "The open ports are common for a television.";
    case "computer":
      return "The open ports are common for a Windows computer.";
    case "apple":
      return "The open ports are common for an Apple device.";
    default:
      return "";
  }
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

function PortSummary({
  services,
}: {
  services: { port: number; state: string; label?: string; summary?: string }[];
}) {
  if (services.length === 0) {
    return null;
  }
  const open = services.filter((service) => service.state === "open");
  const closed = services.filter((service) => service.state !== "open").length;
  return (
    <div className="mt-3 text-stone-600">
      <span className="block">
        {open.length > 0 ? `Open ports: ${open.map((service) => service.port).join(", ")}.` : "No common ports were open."}
        {closed > 0 ? ` ${closed} other checked ports were closed or did not answer.` : ""}
      </span>
      {open.length > 0 && (
        <ul className="mt-2 space-y-2">
          {open.map((service) => (
            <li key={service.port} className="rounded-2xl bg-stone-50 px-3 py-2">
              <span className={`mr-2 inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${labelTone(service.label)}`}>
                Port {service.port}. {portLabel(service.label)}
              </span>
              <span className="text-stone-700">{service.summary}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function labelTone(label: string | undefined) {
  if (label === "expected") {
    return "bg-emerald-100 text-emerald-900";
  }
  if (label === "close") {
    return "bg-rose-100 text-rose-900";
  }
  return "bg-amber-100 text-amber-950";
}

function portLabel(label: string | undefined) {
  if (label === "expected") {
    return "Expected.";
  }
  if (label === "close") {
    return "Close it if you do not use it.";
  }
  return "Worth a look.";
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
      return `Finished. ${label} Each open port is explained under the device.`;
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

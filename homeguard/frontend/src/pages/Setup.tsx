import { FormEvent, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { InterfaceInfo, Network, SetupStatus } from "../types";

export function SetupPage() {
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [passphrase, setPassphrase] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const [nextStatus, nextInterfaces, nextNetworks] = await Promise.all([
      api<SetupStatus>("/api/setup"),
      api<InterfaceInfo[]>("/api/interfaces"),
      api<Network[]>("/api/networks"),
    ]);
    setStatus(nextStatus);
    setInterfaces(nextInterfaces);
    setNetworks(nextNetworks);
  }

  useEffect(() => {
    refresh().catch((reason: unknown) => {
      setError(reason instanceof Error ? reason.message : "The API did not respond.");
    });
  }, []);

  async function onPassphrase(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      if (status?.setup_completed) {
        await api<SetupStatus>("/api/session", {
          method: "POST",
          body: JSON.stringify({ passphrase }),
        });
        setMessage("Signed in on this browser.");
      } else {
        await api<SetupStatus>("/api/setup", {
          method: "POST",
          body: JSON.stringify({ passphrase }),
        });
        setMessage("Passphrase stored as a hash. You are signed in.");
      }
      setPassphrase("");
      await refresh();
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function confirmNetwork(network: Network) {
    setError(null);
    setMessage(null);
    try {
      await api<Network>(`/api/networks/${network.id}/confirm`, { method: "POST" });
      setMessage(`${network.cidr} is confirmed. You can look for devices from the dashboard.`);
      await refresh();
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "The network was not confirmed.");
    }
  }

  async function saveSuggested(item: InterfaceInfo) {
    if (!item.suggested_scan_cidr) {
      return;
    }
    setError(null);
    setMessage(null);
    try {
      await api<Network>("/api/networks", {
        method: "POST",
        body: JSON.stringify({
          name: item.name,
          cidr: item.suggested_scan_cidr,
          interface_name: item.name,
        }),
      });
      setMessage(`Saved ${item.suggested_scan_cidr}. Confirm it before looking for devices.`);
      await refresh();
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "The network was not saved.");
    }
  }

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-medium">Setup</h1>
        <p className="mt-2 max-w-2xl text-sm text-stone-600">
          HomeGuard keeps one passphrase on this computer. The hash stays in the local SQLite
          file. Save your home network here, then confirm it before looking for devices.
        </p>
      </section>

      {error && <p className="text-sm text-red-800">{error}</p>}
      {message && <p className="text-sm text-stone-800">{message}</p>}

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <h2 className="text-base font-medium">
          {status?.setup_completed ? "Sign in" : "Create a passphrase"}
        </h2>
        <p className="mt-2 text-sm text-stone-600">
          {status?.authenticated
            ? "This browser has a local session."
            : "Use at least 12 characters. The passphrase is not stored in clear text."}
        </p>
        <form className="mt-4 flex flex-col gap-3 sm:max-w-md" onSubmit={onPassphrase}>
          <label className="text-sm">
            <span className="mb-1 block text-stone-600">Passphrase</span>
            <input
              className="w-full rounded-md border border-stone-300 px-3 py-2"
              type="password"
              autoComplete="new-password"
              minLength={12}
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              required
            />
          </label>
          <button
            className="w-fit rounded-md bg-stone-900 px-4 py-2 text-sm text-stone-50 disabled:opacity-60"
            type="submit"
            disabled={busy}
          >
            {status?.setup_completed ? "Sign in" : "Save passphrase"}
          </button>
        </form>
      </section>

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <h2 className="text-base font-medium">Detected interfaces</h2>
        {interfaces.length === 0 ? (
          <p className="mt-3 text-sm text-stone-600">No non-loopback IPv4 interfaces were found.</p>
        ) : (
          <ul className="mt-4 divide-y divide-stone-200">
            {interfaces.map((item) => (
              <li key={`${item.name}-${item.address}`} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-medium">{item.name}</p>
                  <p className="text-sm text-stone-600">
                    {item.address} · interface {item.interface_cidr || "unknown"}
                    {item.suggested_scan_cidr ? ` · suggested ${item.suggested_scan_cidr}` : ""}
                  </p>
                  {item.detail && <p className="text-sm text-stone-600">{item.detail}</p>}
                </div>
                <button
                  className="w-fit rounded-md border border-stone-400 px-3 py-1.5 text-sm disabled:opacity-50"
                  type="button"
                  disabled={!status?.authenticated || !item.suggested_scan_cidr}
                  onClick={() => saveSuggested(item)}
                >
                  Save suggested /24
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2 className="text-base font-medium">Saved scopes</h2>
        {networks.length === 0 ? (
          <p className="mt-3 text-sm text-stone-600">No networks saved yet.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {networks.map((network) => (
              <li key={network.id} className="flex flex-col gap-2 rounded-md border border-stone-300 bg-white px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between">
                <span>
                  {network.name} · {network.cidr}
                  {network.ownership_confirmed ? " · confirmed" : " · not confirmed"}
                </span>
                {!network.ownership_confirmed && (
                  <button
                    className="w-fit rounded-md border border-stone-400 px-3 py-1.5 text-sm disabled:opacity-50"
                    type="button"
                    disabled={!status?.authenticated}
                    onClick={() => confirmNetwork(network)}
                  >
                    Confirm this network
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

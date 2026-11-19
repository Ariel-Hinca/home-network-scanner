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
  const usable = interfaces.filter((item) => item.suggested_scan_cidr);
  const others = interfaces.filter((item) => !item.suggested_scan_cidr);

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
      setError(reason instanceof Error ? reason.message : "HomeGuard is not running. Start it, then refresh this page.");
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
        setMessage("You are signed in. You can choose your home Wi-Fi below.");
      } else {
        await api<SetupStatus>("/api/setup", {
          method: "POST",
          body: JSON.stringify({ passphrase }),
        });
        setMessage("Your password is saved, and you are signed in. Next, choose your home Wi-Fi below.");
      }
      setPassphrase("");
      await refresh();
    } catch (reason) {
      setError(plainError(reason, "That password was not accepted."));
    } finally {
      setBusy(false);
    }
  }

  async function removeNetwork(network: Network) {
    setError(null);
    setMessage(null);
    try {
      await api<void>(`/api/networks/${network.id}`, { method: "DELETE" });
      setMessage("Removed. You can choose that home network again if you still want it.");
      await refresh();
    } catch (reason) {
      setError(plainError(reason, "That home network could not be removed."));
    }
  }

  async function confirmNetwork(network: Network) {
    setError(null);
    setMessage(null);
    try {
      await api<Network>(`/api/networks/${network.id}/confirm`, { method: "POST" });
      setMessage("You allowed HomeGuard to look at this Wi-Fi. Go to Home and click Look for devices.");
      await refresh();
    } catch (reason) {
      setError(plainError(reason, "HomeGuard could not save your permission."));
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
          name: friendlyConnectionName(item.name),
          cidr: item.suggested_scan_cidr,
          interface_name: item.name,
        }),
      });
      setMessage("This Wi-Fi is saved. Click “This is my home network” before looking for devices.");
      await refresh();
    } catch (reason) {
      if (reason instanceof ApiError && reason.code === "network_already_saved") {
        setMessage(reason.message);
        return;
      }
      setError(plainError(reason, "That Wi-Fi was not saved."));
    }
  }

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-medium">Setup</h1>
        <p className="mt-2 max-w-2xl text-sm text-stone-600">
          Do these two things once. Make a password for this app, then tell HomeGuard which home
          Wi-Fi it is allowed to check. This is not your Wi-Fi password.
        </p>
      </section>

      {error && <p className="text-sm text-red-800">{error}</p>}
      {message && <p className="text-sm text-stone-800">{message}</p>}

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <p className="text-xs uppercase tracking-wide text-stone-500">Step 1</p>
        <h2 className="mt-1 text-base font-medium">
          {status?.setup_completed ? "Sign in" : "Create a password for this app"}
        </h2>
        <p className="mt-2 text-sm text-stone-600">{passwordHelp(status)}</p>
        <form className="mt-4 flex flex-col gap-3 sm:max-w-md" onSubmit={onPassphrase}>
          <label className="text-sm">
            <span className="mb-1 block text-stone-600">Password</span>
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
            {busy ? "Saving…" : status?.setup_completed ? "Sign in" : "Save password"}
          </button>
        </form>
      </section>

      <section className="rounded-lg border border-stone-300 bg-white p-5">
        <p className="text-xs uppercase tracking-wide text-stone-500">Step 2</p>
        <h2 className="mt-1 text-base font-medium">Choose your home Wi-Fi</h2>
        <p className="mt-2 text-sm text-stone-600">
          These are the connections on this computer. Pick the one you use at home. It often starts
          with 192.168. Skip VPN and virtual connections if you are not sure.
        </p>
        {!status?.authenticated && (
          <p className="mt-3 text-sm text-stone-600">Sign in above before you can choose one.</p>
        )}
        {usable.length === 0 ? (
          <p className="mt-3 text-sm text-stone-600">
            No home Wi-Fi was found. Connect this computer to your home network, then refresh the page.
          </p>
        ) : (
          <ul className="mt-4 divide-y divide-stone-200">
            {usable.map((item) => (
              <ConnectionRow
                key={`${item.name}-${item.address}`}
                item={item}
                canSave={Boolean(status?.authenticated)}
                onSave={saveSuggested}
              />
            ))}
          </ul>
        )}
        {others.length > 0 && (
          <details className="mt-4 text-sm text-stone-600">
            <summary className="cursor-pointer">Other connections on this computer</summary>
            <p className="mt-2">These are not your home Wi-Fi. You can ignore them.</p>
            <ul className="mt-2 divide-y divide-stone-200">
              {others.map((item) => (
                <li key={`${item.name}-${item.address}`} className="py-2">
                  {friendlyConnectionName(item.name)} · {item.address}
                </li>
              ))}
            </ul>
          </details>
        )}
      </section>

      <section>
        <p className="text-xs uppercase tracking-wide text-stone-500">Step 3</p>
        <h2 className="mt-1 text-base font-medium">Allow HomeGuard to look</h2>
        {networks.length === 0 ? (
          <p className="mt-3 text-sm text-stone-600">You have not chosen a home network yet.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {networks.map((network) => (
              <li key={network.id} className="flex flex-col gap-2 rounded-md border border-stone-300 bg-white px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between">
                <span>
                  <span className="font-medium">{friendlyConnectionName(network.name)}</span>
                  <span className="mt-1 block text-stone-600">
                    {network.cidr}
                    {network.ownership_confirmed
                      ? " · Ready. You can look for devices from Home."
                      : " · Waiting for you to allow it."}
                  </span>
                </span>
                <span className="flex flex-wrap gap-2">
                  {!network.ownership_confirmed && (
                    <button
                      className="w-fit rounded-md border border-stone-400 px-3 py-1.5 text-sm disabled:opacity-50"
                      type="button"
                      disabled={!status?.authenticated}
                      onClick={() => confirmNetwork(network)}
                    >
                      This is my home network
                    </button>
                  )}
                  <button
                    className="w-fit rounded-md border border-stone-400 px-3 py-1.5 text-sm disabled:opacity-50"
                    type="button"
                    disabled={!status?.authenticated}
                    onClick={() => removeNetwork(network)}
                  >
                    Remove
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function ConnectionRow({
  item,
  canSave,
  onSave,
}: {
  item: InterfaceInfo;
  canSave: boolean;
  onSave: (item: InterfaceInfo) => void;
}) {
  return (
    <li className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <p className="text-sm font-medium">{friendlyConnectionName(item.name)}</p>
        <p className="text-sm text-stone-600">This computer’s address: {item.address}</p>
        <p className="text-sm text-stone-600">Home network to check: {item.suggested_scan_cidr}</p>
      </div>
      <button
        className="w-fit shrink-0 rounded-md border border-stone-400 px-3 py-1.5 text-sm disabled:opacity-50"
        type="button"
        disabled={!canSave}
        onClick={() => onSave(item)}
      >
        Use this network
      </button>
    </li>
  );
}

function passwordHelp(status: SetupStatus | null) {
  if (status?.authenticated) {
    return "You are signed in on this computer.";
  }
  if (status?.setup_completed) {
    return "Type the password you created earlier for this app. It is not your Wi-Fi password.";
  }
  return "Make one up. A short sentence is fine, as long as it has at least 12 characters. HomeGuard remembers it only on this computer.";
}

function friendlyConnectionName(name: string) {
  const known: Record<string, string> = {
    WiFi: "Wi-Fi",
    "Wi-Fi": "Wi-Fi",
    WLAN: "Wi-Fi",
    Ethernet: "Ethernet cable",
  };
  return known[name] ?? name;
}

function plainError(reason: unknown, fallback: string) {
  if (!(reason instanceof ApiError)) {
    return fallback;
  }
  if (reason.status === 401) {
    return "That password does not match. Try the one you created the first time.";
  }
  if (reason.message.trim().length > 0) {
    return reason.message;
  }
  return fallback;
}

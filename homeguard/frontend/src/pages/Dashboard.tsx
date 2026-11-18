import { FormEvent, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import type { Health, ValidatedCidr } from "../types";

export function DashboardPage() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const [cidr, setCidr] = useState("192.168.1.0/24");
  const [result, setResult] = useState<ValidatedCidr | null>(null);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

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

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-medium">Dashboard</h1>
        <p className="mt-2 max-w-2xl text-sm text-stone-600">
          Phase 0 checks that this service is local and that a target is a private network
          no larger than /16. Scanning starts in a later phase.
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
              <dt className="text-xs uppercase tracking-wide text-stone-500">Bind</dt>
              <dd className="mt-1 text-sm">
                {health.api_host}:{health.api_port}
              </dd>
            </div>
            <div className="sm:col-span-3">
              <dt className="text-xs uppercase tracking-wide text-stone-500">Allowed ranges</dt>
              <dd className="mt-1 text-sm">{health.scope_policy.allowed_ranges.join(", ")}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Largest scope</dt>
              <dd className="mt-1 text-sm">{health.scope_policy.max_scope}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-stone-500">Default size</dt>
              <dd className="mt-1 text-sm">{health.scope_policy.default_scope}</dd>
            </div>
          </dl>
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

"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { CheckCircle2, RefreshCw, Server, XCircle } from "lucide-react";
import { Badge, Spinner } from "@/components/ui";
import type { HealthResponse } from "@/lib/types";

export default function SettingsPage() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [apiUrl, setApiUrl] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [savedApiUrl, setSavedApiUrl] = useState("");

  useEffect(() => {
    const timer = setTimeout(() => {
      const stored = window.localStorage.getItem("verity_api_url") ?? "";
      setApiUrl(stored);
      setSavedApiUrl(stored);
    }, 0);
    return () => clearTimeout(timer);
  }, []);

  const check = useCallback(async (base?: string) => {
    setLoading(true);
    setError(null);
    try {
      // The api module reads NEXT_PUBLIC_API_URL at module load; for the
      // health probe here we fetch directly so the user can test a URL.
      const target = (base || process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
      const res = await fetch(`${target}/api/v1/health`, { cache: "no-store" });
      if (!res.ok) throw new Error(`Health check failed with status ${res.status}`);
      setHealth((await res.json()) as HealthResponse);
    } catch (err) {
      setHealth(null);
      setError(err instanceof Error ? err.message : "Health check failed.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => void check(savedApiUrl), 0);
    return () => clearTimeout(timer);
  }, [check, savedApiUrl]);

  return (
    <div className="mx-auto max-w-3xl px-4 py-10 sm:px-6">
      <h1 className="text-2xl font-bold text-white">Settings</h1>
      <p className="mt-1 text-sm text-slate-400">Client-side preferences and backend connection diagnostics.</p>

      {/* Backend connection */}
      <div className="card mt-6 p-6">
        <h2 className="flex items-center gap-2 font-semibold text-white">
          <Server className="h-5 w-5 text-cyan-400" /> Backend connection
        </h2>
        <p className="mt-2 text-sm text-slate-400">
          Default API base URL comes from the <code className="font-mono text-xs text-cyan-300">NEXT_PUBLIC_API_URL</code>{" "}
          environment variable ({process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000"}). You can override it
          locally for testing — the override is stored in this browser only.
        </p>
        <div className="mt-4 flex flex-col gap-3 sm:flex-row">
          <input
            className="input flex-1 font-mono text-sm"
            placeholder="https://your-backend.example.com"
            value={apiUrl}
            onChange={(e) => setApiUrl(e.target.value)}
            aria-label="Backend base URL override"
          />
          <button
            className="btn-primary shrink-0 text-sm"
            onClick={() => {
              const trimmed = apiUrl.trim().replace(/\/$/, "");
              if (trimmed) window.localStorage.setItem("verity_api_url", trimmed);
              else window.localStorage.removeItem("verity_api_url");
              setSavedApiUrl(trimmed);
              void check(trimmed);
            }}
          >
            Save & test
          </button>
        </div>

        <div className="mt-4">
          {loading ? (
            <Spinner />
          ) : health ? (
            <div className="flex items-start gap-3 rounded-lg border border-emerald-400/30 bg-emerald-400/5 p-4">
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" />
              <div className="text-sm">
                <p className="font-medium text-emerald-200">Backend healthy</p>
                <p className="mt-1 text-slate-400">
                  {health.service} v{health.version} · environment {health.environment}
                </p>
              </div>
            </div>
          ) : (
            <div className="flex items-start gap-3 rounded-lg border border-rose-500/30 bg-rose-500/5 p-4">
              <XCircle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
              <div className="text-sm">
                <p className="font-medium text-rose-200">Backend unreachable</p>
                <p className="mt-1 text-slate-400">{error}</p>
              </div>
            </div>
          )}
        </div>
        <button onClick={() => void check(savedApiUrl)} className="btn-secondary mt-4 text-sm">
          <RefreshCw className="h-4 w-4" /> Re-test connection
        </button>
      </div>

      {/* Data & privacy */}
      <div className="card mt-6 p-6">
        <h2 className="font-semibold text-white">Data & privacy</h2>
        <ul className="mt-3 space-y-2 text-sm text-slate-400">
          <li>• URLs are redacted before persistence — sensitive query parameters are never stored.</li>
          <li>• Threat-intelligence queries are redacted (no query strings sent to providers).</li>
          <li>• No API keys or database credentials are ever exposed through the UI or the API.</li>
          <li>• Scores are heuristic and never presented as probabilities.</li>
        </ul>
        <div className="mt-4 flex flex-wrap gap-2">
          <Badge className="border-emerald-400/30 bg-emerald-400/10 text-emerald-300">SSRF guard active</Badge>
          <Badge className="border-emerald-400/30 bg-emerald-400/10 text-emerald-300">Private IP blocking</Badge>
          <Badge className="border-emerald-400/30 bg-emerald-400/10 text-emerald-300">DNS rebinding protection</Badge>
          <Badge className="border-emerald-400/30 bg-emerald-400/10 text-emerald-300">TLS verification</Badge>
        </div>
      </div>

      <p className="mt-6 text-sm text-slate-500">
        Looking for background on the platform? Visit the{" "}
        <Link href="/about" className="text-cyan-400">
          About
        </Link>{" "}
        page.
      </p>
    </div>
  );
}

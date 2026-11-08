"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Loader2, MinusCircle, Radar, Search, ShieldAlert } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { Badge, ErrorState, Spinner } from "@/components/ui";
import type {
  IntelligenceCheckResponse,
  IntelligenceStatusResponse,
  IntelligenceMatch,
} from "@/lib/types";

const MATCH_STYLES: Record<string, string> = {
  confirmed: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  unknown: "border-amber-400/30 bg-amber-400/10 text-amber-300",
};

export default function IntelligencePage() {
  const [status, setStatus] = useState<IntelligenceStatusResponse | null>(null);
  const [url, setUrl] = useState("");
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<IntelligenceCheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    setLoading(true);
    setStatusError(null);
    try {
      setStatus(await api.intelligenceStatus());
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : "Failed to load provider status.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => void loadStatus(), 0);
    return () => clearTimeout(timer);
  }, [loadStatus]);

  async function handleCheck(e: React.SubmitEvent) {
    e.preventDefault();
    if (!url.trim() || checking) return;
    setChecking(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.intelligenceCheck(url.trim()));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unexpected error during intelligence lookup.");
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="glow-bg min-h-[calc(100vh-4rem-4.5rem)]">
      <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6">
        <h1 className="text-2xl font-bold text-white">Threat Intelligence</h1>
        <p className="mt-1 text-sm text-slate-400">
          Passive lookups across configured threat-intelligence providers. No connection is made to the target;
          query strings are redacted before any external submission.
        </p>

        {/* Provider status — real backend states */}
        <div className="card mt-6 p-6">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white">Provider status</h2>
            <button onClick={loadStatus} className="btn-secondary px-3 py-1.5 text-xs">
              Refresh
            </button>
          </div>
          {loading ? (
            <Spinner />
          ) : statusError ? (
            <div className="mt-4">
              <ErrorState message={statusError} onRetry={loadStatus} />
            </div>
          ) : (
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              {status?.providers.map((p) => (
                <div key={p.provider} className="flex items-center justify-between rounded-lg border border-slate-800/60 bg-slate-900/40 px-4 py-3">
                  <div className="flex items-center gap-2">
                    <Radar className="h-4 w-4 text-cyan-400" />
                    <span className="text-sm capitalize text-slate-200">{p.provider}</span>
                  </div>
                  <Badge
                    className={
                      p.configured && p.enabled
                        ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                        : "border-slate-600/40 bg-slate-700/20 text-slate-400"
                    }
                  >
                    {p.configured && p.enabled ? "ACTIVE" : p.enabled ? "NOT CONFIGURED" : "DISABLED"}
                  </Badge>
                </div>
              ))}
            </div>
          )}
          {status && (
            <p className="mt-3 text-xs text-slate-500">
              Missing API keys mean providers report honest UNAVAILABLE states — never fabricated clean results.
              Credentials are never exposed (credentials_exposed: {String(status.credentials_exposed)}).
            </p>
          )}
        </div>

        {/* Lookup form */}
        <div className="card mt-6 p-6">
          <h2 className="font-semibold text-white">Check a URL or domain</h2>
          <form onSubmit={handleCheck} className="mt-4 flex flex-col gap-3 sm:flex-row">
            <input
              className="input flex-1 font-mono text-sm"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={checking}
              aria-label="URL to check against threat intelligence"
            />
            <button type="submit" className="btn-primary shrink-0 text-sm" disabled={checking || !url.trim()}>
              {checking ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              {checking ? "Checking…" : "Check"}
            </button>
          </form>

          {error && (
            <div className="mt-4 flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 text-sm text-rose-200">
              <AlertTriangle className="h-4 w-4" /> {error}
            </div>
          )}

          {result && (
            <div className="animate-fade-up mt-6">
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4 text-center">
                  <p className="text-2xl font-bold text-white">{result.providers_checked}</p>
                  <p className="text-xs text-slate-500">providers checked</p>
                </div>
                <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4 text-center">
                  <p className="text-2xl font-bold text-amber-300">{result.matches_found}</p>
                  <p className="text-xs text-slate-500">matches found</p>
                </div>
                <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4 text-center">
                  <p className="text-2xl font-bold text-rose-300">{result.verified_matches}</p>
                  <p className="text-xs text-slate-500">verified matches</p>
                </div>
              </div>

              {result.matches.length === 0 ? (
                <div className="mt-4 flex items-start gap-3 rounded-lg border border-slate-800/60 bg-slate-900/40 p-4 text-sm text-slate-300">
                  <MinusCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" />
                  <span>
                    No matches reported by the checked providers. {result.disclaimer}
                  </span>
                </div>
              ) : (
                <div className="mt-4 space-y-3">
                  {result.matches.map((m: IntelligenceMatch, i: number) => (
                    <div key={i} className="card p-4">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={MATCH_STYLES[m.verification_status] ?? MATCH_STYLES.unknown}>
                          {m.verification_status}
                        </Badge>
                        <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">{m.provider}</Badge>
                        {m.threat_category && (
                          <Badge className="border-rose-500/30 bg-rose-500/10 text-rose-300">{m.threat_category}</Badge>
                        )}
                        <span className="font-mono text-xs text-slate-400">{m.indicator_type}: {m.indicator_value}</span>
                      </div>
                      {m.detail && <p className="mt-2 text-sm text-slate-300">{m.detail}</p>}
                    </div>
                  ))}
                </div>
              )}
              <p className="mt-4 flex items-start gap-2 text-xs text-slate-500">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {result.disclaimer}
              </p>
            </div>
          )}
        </div>

        {/* Honest-state legend */}
        <div className="card mt-6 p-6">
          <h2 className="font-semibold text-white">Verification statuses</h2>
          <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
            <div className="flex items-center gap-2 text-rose-300">
              <CheckCircle2 className="h-4 w-4" /> confirmed — provider verified the indicator
            </div>
            <div className="flex items-center gap-2 text-amber-300">
              <AlertTriangle className="h-4 w-4" /> unknown — match reported without verification
            </div>
            <div className="flex items-center gap-2 text-slate-400">
              <MinusCircle className="h-4 w-4" /> unavailable — provider unreachable or not configured
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

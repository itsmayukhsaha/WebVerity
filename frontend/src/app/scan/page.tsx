"use client";

import { useState } from "react";
import Link from "next/link";
import { AlertTriangle, Loader2, ScanSearch, ShieldAlert } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { RISK_BANDS } from "@/lib/format";
import { RiskGauge } from "@/components/ui";
import type { ScanResponse } from "@/lib/types";

export default function ScanPage() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function handleSubmit(e: React.SubmitEvent) {
    e.preventDefault();
    if (!url.trim() || scanning) return;
    // Basic client-side scheme validation — the backend performs authoritative
    // validation and SSRF enforcement.
    const trimmed = url.trim();
    if (!/^https?:\/\//i.test(trimmed) && !/^[\w-]+(\.[\w-]+)+/.test(trimmed)) {
      setError("Enter a valid URL, e.g. https://example.com");
      return;
    }
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const scan = await api.submitScan(trimmed.startsWith("http") ? trimmed : `https://${trimmed}`);
      setResult(scan);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unexpected error while scanning.");
    } finally {
      setScanning(false);
    }
  }

  const band = result ? RISK_BANDS[result.threat_assessment.classification] : null;

  return (
    <div className="glow-bg min-h-[calc(100vh-4rem-4.5rem)]">
      <div className="mx-auto max-w-4xl px-4 py-16 sm:px-6">
        <h1 className="text-center text-3xl font-bold text-white">Website Security Scanner</h1>
        <p className="mx-auto mt-3 max-w-xl text-center text-slate-400">
          Submit a public URL for a full multi-layer assessment: URL structure, DNS, TLS, HTTP security,
          redirects, content, domain registration, and threat intelligence.
        </p>

        <form onSubmit={handleSubmit} className="mx-auto mt-10 flex max-w-2xl flex-col gap-3 sm:flex-row">
          <input
            className="input flex-1 font-mono text-sm"
            type="text"
            inputMode="url"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={scanning}
            aria-label="URL to scan"
          />
          <button type="submit" className="btn-primary shrink-0" disabled={scanning || !url.trim()}>
            {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}
            {scanning ? "Scanning…" : "Scan"}
          </button>
        </form>

        {scanning && (
          <div className="card mx-auto mt-8 max-w-2xl p-6 text-center">
            <Loader2 className="mx-auto h-6 w-6 animate-spin text-cyan-400" />
            <p className="mt-3 text-sm text-slate-300">Running the 8-module assessment pipeline…</p>
            <p className="mt-1 text-xs text-slate-500">DNS, TLS, HTTP, redirects, content, RDAP and threat feeds.</p>
          </div>
        )}

        {error && (
          <div className="card mx-auto mt-8 flex max-w-2xl items-start gap-3 border-rose-500/30 bg-rose-500/5 p-5">
            {error.toLowerCase().includes("security") ? (
              <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" />
            ) : (
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
            )}
            <div>
              <p className="font-medium text-rose-200">{error}</p>
              <p className="mt-1 text-xs text-slate-400">
                Requests for private, loopback, or metadata addresses are rejected by the SSRF guard by design.
              </p>
            </div>
          </div>
        )}

        {result && band && (
          <div className="animate-fade-up mt-12">
            <div className="card p-6 sm:p-8">
              <div className="flex flex-col items-center gap-6 sm:flex-row sm:justify-between">
                <div>
                  <p className="text-xs uppercase tracking-wider text-slate-500">Scan complete</p>
                  <h2 className="mt-1 break-all font-mono text-xl text-white">{result.target}</h2>
                  <p className="mt-1 text-xs text-slate-500">Scan ID: {result.scan_id}</p>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs">
                    <span className={`rounded-full border px-2.5 py-0.5 ${band.border} ${band.bg} ${band.color}`}>
                      {band.label}
                    </span>
                    <span className="rounded-full border border-slate-600/40 bg-slate-700/20 px-2.5 py-0.5 text-slate-300">
                      Confidence: {result.threat_assessment.confidence}
                    </span>
                    <span className="rounded-full border border-slate-600/40 bg-slate-700/20 px-2.5 py-0.5 text-slate-300">
                      Modules: {String(result.scan_metadata?.modules_completed ?? "—")}/{String(result.scan_metadata?.modules_total ?? "8")}
                    </span>
                  </div>
                </div>
                <RiskGauge score={result.threat_assessment.risk_score} />
              </div>
              {result.threat_assessment.explanation && (
                <p className="mt-6 rounded-lg border border-slate-800/60 bg-slate-900/40 p-4 text-sm text-slate-300">
                  {result.threat_assessment.explanation}
                </p>
              )}
              <p className="mt-4 text-xs text-slate-500">
                Heuristic score — not a probability. Absence of threat indicators does not guarantee the website is safe.
              </p>
              <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                <Link href={`/scan/${result.scan_id}`} className="btn-primary">
                  View full report
                </Link>
                <button
                  className="btn-secondary"
                  onClick={() => {
                    setResult(null);
                    setUrl("");
                  }}
                >
                  Scan another URL
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

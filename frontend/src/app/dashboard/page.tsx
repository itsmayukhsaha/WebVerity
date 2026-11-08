"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Activity, Database, Gauge, RefreshCw, ScanSearch, ShieldCheck, Zap } from "lucide-react";
import { api } from "@/lib/api";
import { RISK_BANDS, formatDate } from "@/lib/format";
import { Badge, ErrorState, Spinner } from "@/components/ui";
import type { IntelligenceStatusResponse, ScanHistoryItem, ScanHistoryResponse } from "@/lib/types";

interface DashboardData {
  history: ScanHistoryResponse;
  intelligence: IntelligenceStatusResponse;
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [history, intelligence] = await Promise.all([
        api.listScans({ limit: 100 }),
        api.intelligenceStatus(),
      ]);
      setData({ history, intelligence });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => void load(), 0);
    return () => clearTimeout(timer);
  }, [load]);

  if (loading) return <Spinner label="Loading dashboard…" />;
  if (error || !data)
    return (
      <div className="mx-auto max-w-3xl px-4 py-16">
        <ErrorState message={error ?? "Dashboard unavailable."} onRetry={load} />
      </div>
    );

  const scans = data.history.scans;
  const completed = scans.filter((s) => s.status === "COMPLETED");
  const avgRisk = completed.length
    ? Math.round(completed.reduce((sum, s) => sum + s.risk_score, 0) / completed.length)
    : 0;
  const avgPosture = completed.length
    ? Math.round(completed.reduce((sum, s) => sum + s.security_posture_score, 0) / completed.length)
    : 0;

  const byRisk = { LOW: 0, MODERATE: 0, HIGH: 0, CRITICAL: 0 } as Record<string, number>;
  for (const s of completed) byRisk[s.risk_level] = (byRisk[s.risk_level] ?? 0) + 1;

  const providers = data.intelligence.providers;
  const activeProviders = providers.filter((p) => p.configured && p.enabled).length;

  const stats = [
    { icon: Database, label: "Total scans", value: String(data.history.total), accent: "text-cyan-400" },
    { icon: Gauge, label: "Avg threat risk", value: `${avgRisk}/100`, accent: "text-blue-400" },
    { icon: ShieldCheck, label: "Avg posture", value: `${avgPosture}/100`, accent: "text-violet-400" },
    { icon: Zap, label: "Active intel providers", value: `${activeProviders}/${providers.length}`, accent: "text-emerald-400" },
  ];

  return (
    <div className="glow-bg min-h-[calc(100vh-4rem-4.5rem)]">
      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
            <p className="mt-1 text-sm text-slate-400">Live overview of scan activity and threat intelligence availability.</p>
          </div>
          <button onClick={load} className="btn-secondary text-sm" aria-label="Refresh dashboard">
            <RefreshCw className="h-4 w-4" />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>

        {/* Stat cards */}
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {stats.map((s) => (
            <div key={s.label} className="card card-hover p-5">
              <s.icon className={`h-6 w-6 ${s.accent}`} />
              <p className="mt-3 text-2xl font-bold text-white">{s.value}</p>
              <p className="text-sm text-slate-500">{s.label}</p>
            </div>
          ))}
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          {/* Risk distribution (real counts) */}
          <div className="card p-6">
            <h2 className="font-semibold text-white">Risk distribution</h2>
            <p className="mt-1 text-xs text-slate-500">Completed scans by classification</p>
            <div className="mt-5 space-y-3">
              {(["LOW", "MODERATE", "HIGH", "CRITICAL"] as const).map((level) => {
                const count = byRisk[level] ?? 0;
                const pct = completed.length ? (count / completed.length) * 100 : 0;
                const band = RISK_BANDS[level];
                return (
                  <div key={level}>
                    <div className="flex justify-between text-xs">
                      <span className="text-slate-300">{band.label}</span>
                      <span className="text-slate-500">{count}</span>
                    </div>
                    <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full ${band.color.replace("text-", "bg-")}`}
                        style={{ width: `${pct}%`, transition: "width 0.6s ease" }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Intel provider health (real backend states) */}
          <div className="card p-6">
            <h2 className="font-semibold text-white">Threat intelligence</h2>
            <p className="mt-1 text-xs text-slate-500">Provider configuration state (no credentials exposed)</p>
            <div className="mt-5 space-y-3">
              {providers.map((p) => (
                <div key={p.provider} className="flex items-center justify-between rounded-lg border border-slate-800/60 bg-slate-900/40 px-3 py-2.5">
                  <span className="text-sm capitalize text-slate-200">{p.provider}</span>
                  <Badge
                    className={
                      p.configured && p.enabled
                        ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
                        : "border-slate-600/40 bg-slate-700/20 text-slate-400"
                    }
                  >
                    {p.configured && p.enabled ? "active" : p.enabled ? "not configured" : "disabled"}
                  </Badge>
                </div>
              ))}
            </div>
            <Link href="/intelligence" className="mt-4 inline-flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
              <Activity className="h-3.5 w-3.5" /> Threat intel center
            </Link>
          </div>

          {/* Quick actions */}
          <div className="card flex flex-col gap-3 p-6">
            <h2 className="font-semibold text-white">Quick actions</h2>
            <Link href="/scan" className="btn-primary w-full">
              <ScanSearch className="h-4 w-4" /> New scan
            </Link>
            <Link href="/history" className="btn-secondary w-full">
              Browse scan history
            </Link>
            <Link href="/analytics" className="btn-secondary w-full">
              View analytics
            </Link>
            <p className="mt-auto text-xs text-slate-500">
              All figures come from persisted scan records — nothing on this page is estimated.
            </p>
          </div>
        </div>

        {/* Recent scans */}
        <div className="card mt-6 p-6">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-white">Recent scans</h2>
            <Link href="/history" className="text-sm text-cyan-400 hover:text-cyan-300">
              View all
            </Link>
          </div>
          {scans.length === 0 ? (
            <p className="mt-6 text-center text-sm text-slate-400">
              No scans yet. Run your first scan from the <Link href="/scan" className="text-cyan-400">scanner</Link>.
            </p>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-500">
                    <th className="py-2 pr-4">Target</th>
                    <th className="py-2 pr-4">Risk</th>
                    <th className="py-2 pr-4">Score</th>
                    <th className="py-2 pr-4">Posture</th>
                    <th className="py-2 pr-4">When</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.slice(0, 8).map((s: ScanHistoryItem) => {
                    const band = RISK_BANDS[s.risk_level];
                    return (
                      <tr key={s.scan_id} className="border-b border-slate-800/50 last:border-0">
                        <td className="max-w-[16rem] truncate py-2.5 pr-4">
                          <Link href={`/scan/${s.scan_id}`} className="font-mono text-slate-200 hover:text-cyan-300">
                            {s.target}
                          </Link>
                        </td>
                        <td className="py-2.5 pr-4">
                          <Badge className={`${band.border} ${band.bg} ${band.color}`}>{s.risk_level}</Badge>
                        </td>
                        <td className="py-2.5 pr-4 text-slate-300">{s.risk_score}</td>
                        <td className="py-2.5 pr-4 text-slate-300">{s.security_posture_score}</td>
                        <td className="py-2.5 pr-4 text-slate-500">{formatDate(s.created_at)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

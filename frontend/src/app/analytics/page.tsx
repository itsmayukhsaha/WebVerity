"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { ErrorState, Spinner } from "@/components/ui";
import type { ScanHistoryItem } from "@/lib/types";

const RISK_COLORS: Record<string, string> = {
  LOW: "#34d399",
  MODERATE: "#fbbf24",
  HIGH: "#fb923c",
  CRITICAL: "#f43f5e",
};

interface AnalyticsData {
  items: ScanHistoryItem[];
  total: number;
}

export default function AnalyticsPage() {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listScans({ limit: 100 });
      setData({ items: res.scans, total: res.total });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load analytics.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => void load(), 0);
    return () => clearTimeout(timer);
  }, [load]);

  if (loading) return <Spinner label="Loading analytics…" />;
  if (error || !data)
    return (
      <div className="mx-auto max-w-3xl px-4 py-16">
        <ErrorState message={error ?? "Analytics unavailable."} onRetry={load} />
      </div>
    );

  const completed = data.items.filter((s) => s.status === "COMPLETED");

  // Risk-level distribution (real persisted counts)
  const riskData = (["LOW", "MODERATE", "HIGH", "CRITICAL"] as const)
    .map((level) => ({
      name: level,
      value: completed.filter((s) => s.risk_level === level).length,
    }))
    .filter((d) => d.value > 0);

  // Daily scan volume from real timestamps (last 14 days)
  const daily: { day: string; count: number }[] = [];
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    daily.push({ day: key.slice(5), count: 0 });
  }
  for (const s of completed) {
    const bucket = daily.find((d) => s.created_at.slice(5, 10) === d.day);
    if (bucket) bucket.count += 1;
  }

  const topDomains = Object.entries(
    completed.reduce<Record<string, number>>((acc, s) => {
      acc[s.target] = (acc[s.target] ?? 0) + 1;
      return acc;
    }, {}),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([domain, count]) => ({ domain, count }));

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Analytics & Reports</h1>
          <p className="mt-1 text-sm text-slate-400">
            Visual reports computed from {data.total} persisted scan record{data.total === 1 ? "" : "s"}.
          </p>
        </div>
        <button onClick={load} className="btn-secondary text-sm">
          <RefreshCw className="h-4 w-4" /> <span className="hidden sm:inline">Refresh</span>
        </button>
      </div>

      {completed.length === 0 ? (
        <div className="card mt-8 p-10 text-center">
          <p className="font-semibold text-slate-200">No completed scans yet</p>
          <p className="mt-2 text-sm text-slate-400">
            Analytics appear once scans are recorded.{" "}
            <Link href="/scan" className="text-cyan-400">
              Run your first scan
            </Link>
            .
          </p>
        </div>
      ) : (
        <div className="mt-8 grid gap-4 lg:grid-cols-2">
          <div className="card p-6">
            <h2 className="font-semibold text-white">Risk classification distribution</h2>
            <p className="mt-1 text-xs text-slate-500">Completed scans by threat-risk classification</p>
            <div className="mt-4 h-72">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={riskData} dataKey="value" nameKey="name" innerRadius={60} outerRadius={100} paddingAngle={3}>
                    {riskData.map((entry) => (
                      <Cell key={entry.name} fill={RISK_COLORS[entry.name] ?? "#3b82f6"} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: "#101b33", border: "1px solid #223257", borderRadius: 8, color: "#e2e8f0" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 flex flex-wrap justify-center gap-4 text-xs">
              {riskData.map((d) => (
                <span key={d.name} className="flex items-center gap-1.5 text-slate-300">
                  <span className="h-2.5 w-2.5 rounded-full" style={{ background: RISK_COLORS[d.name] }} />
                  {d.name} ({d.value})
                </span>
              ))}
            </div>
          </div>

          <div className="card p-6">
            <h2 className="font-semibold text-white">Scan volume — last 14 days</h2>
            <p className="mt-1 text-xs text-slate-500">Completed scans per day</p>
            <div className="mt-4 h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={daily}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#223257" vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: "#64748b", fontSize: 11 }} />
                  <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: "#101b33", border: "1px solid #223257", borderRadius: 8, color: "#e2e8f0" }}
                  />
                  <Bar dataKey="count" fill="#22d3ee" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card p-6 lg:col-span-2">
            <h2 className="font-semibold text-white">Most scanned domains</h2>
            <p className="mt-1 text-xs text-slate-500">Top targets across completed scans</p>
            <div className="mt-4 h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topDomains} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#223257" horizontal={false} />
                  <XAxis type="number" allowDecimals={false} tick={{ fill: "#64748b", fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="domain"
                    width={160}
                    tick={{ fill: "#94a3b8", fontSize: 11, fontFamily: "monospace" }}
                  />
                  <Tooltip
                    contentStyle={{ background: "#101b33", border: "1px solid #223257", borderRadius: 8, color: "#e2e8f0" }}
                  />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

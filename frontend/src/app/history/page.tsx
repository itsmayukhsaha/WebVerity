"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Filter, RefreshCw, Search } from "lucide-react";
import { api } from "@/lib/api";
import { RISK_BANDS, formatDate } from "@/lib/format";
import { Badge, EmptyState, ErrorState, Spinner } from "@/components/ui";
import type { ScanHistoryItem } from "@/lib/types";

const RISK_FILTERS = ["ALL", "LOW", "MODERATE", "HIGH", "CRITICAL"];
const STATUS_FILTERS = ["ALL", "COMPLETED", "FAILED", "PROCESSING", "PENDING"];
const PAGE_SIZE = 20;

export default function HistoryPage() {
  const [search, setSearch] = useState("");
  const [risk, setRisk] = useState("ALL");
  const [status, setStatus] = useState("ALL");
  const [page, setPage] = useState(0);
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [submittedSearch, setSubmittedSearch] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.listScans({
        search: submittedSearch || undefined,
        risk_level: risk !== "ALL" ? risk : undefined,
        status: status !== "ALL" ? status : undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      });
      setItems(res.scans);
      setTotal(res.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan history.");
    } finally {
      setLoading(false);
    }
  }, [submittedSearch, risk, status, page]);

  useEffect(() => {
    const timer = setTimeout(() => void load(), 0);
    return () => clearTimeout(timer);
  }, [load]);

  function submitSearch(e: React.SubmitEvent) {
    e.preventDefault();
    setPage(0);
    setSubmittedSearch(search.trim());
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
      <h1 className="text-2xl font-bold text-white">Scan History</h1>
      <p className="mt-1 text-sm text-slate-400">
        All persisted scans with search and filtering — {total} record{total === 1 ? "" : "s"} in the database.
      </p>

      {/* Controls */}
      <div className="card mt-6 p-4">
        <form onSubmit={submitSearch} className="flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              className="input pl-9"
              placeholder="Search by domain or URL…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Search scans"
            />
          </div>
          <button type="submit" className="btn-primary shrink-0 text-sm">
            <Search className="h-4 w-4" /> Search
          </button>
          <button
            type="button"
            className="btn-secondary shrink-0 text-sm"
            onClick={() => {
              setSearch("");
              setSubmittedSearch("");
              setRisk("ALL");
              setStatus("ALL");
              setPage(0);
            }}
          >
            <RefreshCw className="h-4 w-4" /> Reset
          </button>
        </form>
        <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center">
          <span className="flex items-center gap-1.5 text-xs text-slate-500">
            <Filter className="h-3.5 w-3.5" /> Risk:
          </span>
          <div className="flex flex-wrap gap-1.5">
            {RISK_FILTERS.map((r) => (
              <button
                key={r}
                onClick={() => {
                  setRisk(r);
                  setPage(0);
                }}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${risk === r ? "bg-cyan-400/10 text-cyan-300" : "text-slate-400 hover:bg-slate-800/60"
                  }`}
              >
                {r}
              </button>
            ))}
          </div>
          <span className="text-xs text-slate-500 sm:ml-4">Status:</span>
          <div className="flex flex-wrap gap-1.5">
            {STATUS_FILTERS.map((s) => (
              <button
                key={s}
                onClick={() => {
                  setStatus(s);
                  setPage(0);
                }}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${status === s ? "bg-violet-400/10 text-violet-300" : "text-slate-400 hover:bg-slate-800/60"
                  }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      {loading ? (
        <Spinner label="Loading history…" />
      ) : error ? (
        <div className="mt-6">
          <ErrorState message={error} onRetry={load} />
        </div>
      ) : items.length === 0 ? (
        <div className="mt-6">
          <EmptyState
            title="No scans match"
            description="Adjust the search or filters, or run a new scan from the scanner page."
          />
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {items.map((item) => {
            const band = RISK_BANDS[item.risk_level];
            return (
              <Link key={item.scan_id} href={`/scan/${item.scan_id}`} className="card card-hover block p-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm text-white">{item.target}</p>
                    <p className="truncate text-xs text-slate-500">{item.url}</p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge className={`${band.border} ${band.bg} ${band.color}`}>
                      {item.risk_level} · {item.risk_score}
                    </Badge>
                    <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">
                      Posture {item.security_posture_score}
                    </Badge>
                    <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-400">{item.status}</Badge>
                    <span className="text-slate-500">{formatDate(item.created_at)}</span>
                  </div>
                </div>
              </Link>
            );
          })}

          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-3 pt-4 text-sm text-slate-400">
              <button
                className="btn-secondary px-3 py-1.5 text-xs"
                disabled={page === 0}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </button>
              <span>
                Page {page + 1} of {totalPages}
              </span>
              <button
                className="btn-secondary px-3 py-1.5 text-xs"
                disabled={page >= totalPages - 1}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

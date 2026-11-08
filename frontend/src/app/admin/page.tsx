"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, KeyRound, Lock, ScrollText, ShieldAlert, XCircle } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { Badge, EmptyState, ErrorState, Spinner } from "@/components/ui";
import type { AuditLogEntry, CommunitySubmission } from "@/lib/types";

const TOKEN_KEY = "webverity_admin_token";

const STATUS_STYLES: Record<string, string> = {
  PENDING: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  APPROVED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-300",
  REJECTED: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  INFO_REQUESTED: "border-violet-400/30 bg-violet-400/10 text-violet-300",
};

export default function AdminPage() {
  const [token, setToken] = useState("");
  const [tokenInput, setTokenInput] = useState("");
  const [submissions, setSubmissions] = useState<CommunitySubmission[]>([]);
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async (t: string) => {
    setLoading(true);
    setError(null);
    try {
      // Pending listing works for everyone; audit logs verify ADMIN access.
      const [subs, audit] = await Promise.all([
        api.listSubmissions({ status_filter: "PENDING", limit: 100 }),
        api.getAuditLogs(t, 30).catch(() => null),
      ]);
      setSubmissions(subs.submissions);
      setLogs(audit?.logs ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load review queue.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const stored = typeof window !== "undefined" ? sessionStorage.getItem(TOKEN_KEY) ?? "" : "";
    const timer = setTimeout(() => {
      setToken(stored);
      void load(stored);
    }, 0);
    return () => clearTimeout(timer);
  }, [load]);

  function applyToken() {
    const t = tokenInput.trim();
    sessionStorage.setItem(TOKEN_KEY, t);
    setToken(t);
    void load(t);
  }

  async function act(submission: CommunitySubmission, decision: "APPROVED" | "REJECTED" | "INFO_REQUESTED") {
    if (!token) {
      setActionError("Provide an ANALYST or ADMIN bearer token first.");
      return;
    }
    setBusyId(submission.id);
    setActionError(null);
    const notes =
      decision === "INFO_REQUESTED"
        ? window.prompt("What additional evidence is needed?") ?? undefined
        : undefined;
    try {
      await api.reviewSubmission(submission.id, { decision, notes }, token);
      await load(token);
    } catch (err) {
      setActionError(
        err instanceof ApiError ? err.message : "Unexpected error during review action.",
      );
    } finally {
      setBusyId(null);
    }
  }

  if (loading) return <Spinner label="Loading review queue…" />;
  if (error)
    return (
      <div className="mx-auto max-w-3xl px-4 py-16">
        <ErrorState message={error} onRetry={() => load(token)} />
      </div>
    );

  return (
    <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
      <div className="flex items-center gap-3">
        <ShieldAlert className="h-7 w-7 text-violet-400" />
        <div>
          <h1 className="text-2xl font-bold text-white">Intelligence Review</h1>
          <p className="mt-1 text-sm text-slate-400">
            Administrative moderation queue. Review actions are recorded in the audit trail and
            enforced server-side — the token here only unlocks the UI.
          </p>
        </div>
      </div>

      {/* Token gate */}
      <div className="card mt-6 flex flex-col gap-3 p-5 sm:flex-row sm:items-center">
        <KeyRound className="h-5 w-5 shrink-0 text-cyan-400" />
        <input
          type="password"
          className="input flex-1 font-mono text-sm"
          placeholder="Bearer token (ANALYST or ADMIN)"
          value={tokenInput}
          onChange={(e) => setTokenInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyToken()}
          aria-label="Reviewer API token"
        />
        <button className="btn-primary shrink-0" onClick={applyToken}>
          <Lock className="h-4 w-4" /> {token ? "Update token" : "Unlock"}
        </button>
        {token && <Badge className="border-emerald-400/30 bg-emerald-400/10 text-emerald-300">token set</Badge>}
      </div>
      {actionError && <p className="mt-3 text-sm text-rose-300">{actionError}</p>}

      {/* Pending submissions */}
      <h2 className="mt-10 font-semibold text-white">Pending submissions ({submissions.length})</h2>
      {submissions.length === 0 ? (
        <div className="mt-4">
          <EmptyState title="Review queue is empty" description="No submissions awaiting moderation." />
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          {submissions.map((s) => (
            <div key={s.id} className="card p-5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className={STATUS_STYLES[s.status]}>{s.status}</Badge>
                <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">{s.indicator_type}</Badge>
                <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">{s.threat_category}</Badge>
                <span className="ml-auto text-xs text-slate-500">{formatDate(s.created_at)}</span>
              </div>
              <p className="mt-3 break-all font-mono text-sm text-cyan-300">{s.indicator_value}</p>
              <p className="mt-2 text-sm text-slate-300">{s.description}</p>
              {s.evidence && <p className="mt-1 text-xs text-slate-500">Evidence: {s.evidence}</p>}
              <p className="mt-1 text-xs text-slate-500">source: {s.source_name}</p>
              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  className="btn-primary text-xs"
                  disabled={busyId === s.id}
                  onClick={() => act(s, "APPROVED")}
                >
                  <CheckCircle2 className="h-3.5 w-3.5" /> Approve
                </button>
                <button
                  className="btn-secondary border-rose-400/30 text-xs text-rose-300 hover:bg-rose-400/10"
                  disabled={busyId === s.id}
                  onClick={() => act(s, "REJECTED")}
                >
                  <XCircle className="h-3.5 w-3.5" /> Reject
                </button>
                <button
                  className="btn-secondary text-xs"
                  disabled={busyId === s.id}
                  onClick={() => act(s, "INFO_REQUESTED")}
                >
                  Request evidence
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Audit trail */}
      <h2 className="mt-10 flex items-center gap-2 font-semibold text-white">
        <ScrollText className="h-4 w-4 text-violet-400" /> Audit trail
      </h2>
      {logs.length === 0 ? (
        <p className="mt-3 text-sm text-slate-500">
          No audit entries visible. An ADMIN token is required to view the audit trail; review
          actions appear here after they are recorded.
        </p>
      ) : (
        <div className="card mt-4 overflow-x-auto p-4">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-xs uppercase tracking-wider text-slate-500">
                <th className="py-2 pr-4">When</th>
                <th className="py-2 pr-4">Actor</th>
                <th className="py-2 pr-4">Action</th>
                <th className="py-2 pr-4">Resource</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l) => (
                <tr key={l.id} className="border-b border-slate-800/50 last:border-0">
                  <td className="py-2 pr-4 text-slate-500">{formatDate(l.created_at)}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-slate-300">{l.actor_role}</td>
                  <td className="py-2 pr-4 text-slate-200">{l.action}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-slate-500">{l.resource_type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

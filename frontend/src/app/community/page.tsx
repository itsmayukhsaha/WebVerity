"use client";

import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Clock, Send, ShieldQuestion } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import { formatDate } from "@/lib/format";
import { Badge, EmptyState, ErrorState, Spinner } from "@/components/ui";
import type { CommunityMeta, CommunitySubmission, CommunitySubmissionsResponse } from "@/lib/types";

const STATUS_STYLES: Record<string, string> = {
  PENDING: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  APPROVED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-300",
  REJECTED: "border-rose-400/30 bg-rose-400/10 text-rose-300",
  INFO_REQUESTED: "border-violet-400/30 bg-violet-400/10 text-violet-300",
};

const STATUS_ICONS: Record<string, typeof Clock> = {
  PENDING: Clock,
  APPROVED: CheckCircle2,
  REJECTED: AlertTriangle,
  INFO_REQUESTED: ShieldQuestion,
};

export default function CommunityPage() {
  const [data, setData] = useState<CommunitySubmissionsResponse | null>(null);
  const [meta, setMeta] = useState<CommunityMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // submission form state
  const [form, setForm] = useState({
    indicator_type: "domain",
    indicator_value: "",
    threat_category: "phishing",
    description: "",
    evidence: "",
    source_name: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitSuccess, setSubmitSuccess] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [subs, m] = await Promise.all([
        api.listSubmissions({ limit: 50 }),
        api.communityMeta(),
      ]);
      setData(subs);
      setMeta(m);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load community intelligence.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(() => void load(), 0);
    return () => clearTimeout(timer);
  }, [load]);

  async function handleSubmit(e: React.SubmitEvent) {
    e.preventDefault();
    if (submitting) return;
    setSubmitting(true);
    setSubmitError(null);
    setSubmitSuccess(null);
    try {
      const created = await api.createSubmission({
        indicator_type: form.indicator_type,
        indicator_value: form.indicator_value.trim(),
        threat_category: form.threat_category,
        description: form.description.trim(),
        evidence: form.evidence.trim() || undefined,
        source_name: form.source_name.trim() || "anonymous",
      });
      setSubmitSuccess(
        `Submission received (status: ${created.status}). It will be visible after review by an analyst.`,
      );
      setForm({ ...form, indicator_value: "", description: "", evidence: "" });
      await load();
    } catch (err) {
      setSubmitError(err instanceof ApiError ? err.message : "Unexpected error while submitting.");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <Spinner label="Loading community intelligence…" />;
  if (error || !data || !meta)
    return (
      <div className="mx-auto max-w-3xl px-4 py-16">
        <ErrorState message={error ?? "Community intelligence unavailable."} onRetry={load} />
      </div>
    );

  const filtered = data.submissions.filter(
    (s) =>
      (category === "ALL" || s.threat_category === category) &&
      (statusFilter === "ALL" || s.status === statusFilter),
  );

  return (
    <div className="glow-bg min-h-[calc(100vh-4rem-4.5rem)]">
      <div className="mx-auto max-w-7xl px-4 py-10 sm:px-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Community Intelligence</h1>
          <p className="mt-1 text-sm text-slate-400">
            Collaborative threat reporting. Submissions are validated, deduplicated, and held in
            review until an authorized analyst approves them — community data is never treated as
            verified intelligence automatically.
          </p>
        </div>

        {/* Submission form */}
        <form onSubmit={handleSubmit} className="card mt-8 grid gap-4 p-6 sm:grid-cols-2">
          <div>
            <label htmlFor="indicator_type" className="text-xs uppercase tracking-wider text-slate-500">
              Indicator type
            </label>
            <select
              id="indicator_type"
              className="input mt-1"
              value={form.indicator_type}
              onChange={(e) => setForm({ ...form, indicator_type: e.target.value })}
            >
              {meta.indicator_types.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="threat_category" className="text-xs uppercase tracking-wider text-slate-500">
              Threat category
            </label>
            <select
              id="threat_category"
              className="input mt-1"
              value={form.threat_category}
              onChange={(e) => setForm({ ...form, threat_category: e.target.value })}
            >
              {meta.threat_categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="indicator_value" className="text-xs uppercase tracking-wider text-slate-500">
              Indicator value
            </label>
            <input
              id="indicator_value"
              className="input mt-1 font-mono text-sm"
              placeholder="e.g. malicious-domain.net or https://evil-test.net/login"
              value={form.indicator_value}
              onChange={(e) => setForm({ ...form, indicator_value: e.target.value })}
              maxLength={2048}
              required
            />
          </div>
          <div className="sm:col-span-2">
            <label htmlFor="description" className="text-xs uppercase tracking-wider text-slate-500">
              Description (min 10 characters)
            </label>
            <textarea
              id="description"
              className="input mt-1 min-h-[80px] text-sm"
              placeholder="What did you observe? Include context that helps the review."
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              maxLength={4000}
              required
            />
          </div>
          <div>
            <label htmlFor="evidence" className="text-xs uppercase tracking-wider text-slate-500">
              Evidence (optional)
            </label>
            <textarea
              id="evidence"
              className="input mt-1 min-h-[60px] text-sm"
              placeholder="Email headers, screenshots description, observed behaviour…"
              value={form.evidence}
              onChange={(e) => setForm({ ...form, evidence: e.target.value })}
              maxLength={8000}
            />
          </div>
          <div>
            <label htmlFor="source_name" className="text-xs uppercase tracking-wider text-slate-500">
              Source name (optional)
            </label>
            <input
              id="source_name"
              className="input mt-1 text-sm"
              placeholder="anonymous"
              value={form.source_name}
              onChange={(e) => setForm({ ...form, source_name: e.target.value })}
              maxLength={128}
            />
          </div>
          {submitError && <p className="text-sm text-rose-300 sm:col-span-2">{submitError}</p>}
          {submitSuccess && (
            <p className="text-sm text-emerald-300 sm:col-span-2">{submitSuccess}</p>
          )}
          <div className="sm:col-span-2">
            <button type="submit" className="btn-primary" disabled={submitting}>
              <Send className="h-4 w-4" />
              {submitting ? "Submitting…" : "Submit for review"}
            </button>
            <p className="mt-2 text-xs text-slate-500">
              Limit: {meta.rate_limit_per_hour} submissions per hour. Private, loopback and
              metadata addresses are rejected. Submissions are logged for audit.
            </p>
          </div>
        </form>

        {/* Filters */}
        <div className="mt-8 flex flex-wrap items-center gap-3">
          <span className="text-xs uppercase tracking-wider text-slate-500">Category:</span>
          <div className="flex flex-wrap gap-1.5">
            {["ALL", ...meta.threat_categories].map((c) => (
              <button
                key={c}
                onClick={() => setCategory(c)}
                className={`rounded-full border px-3 py-1 text-xs ${category === c
                    ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-300"
                    : "border-slate-700 text-slate-400 hover:text-slate-200"
                  }`}
              >
                {c}
              </button>
            ))}
          </div>
          <span className="ml-4 text-xs uppercase tracking-wider text-slate-500">Status:</span>
          <div className="flex flex-wrap gap-1.5">
            {["ALL", "PENDING", "APPROVED", "INFO_REQUESTED"].map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`rounded-full border px-3 py-1 text-xs ${statusFilter === s
                    ? "border-violet-400/40 bg-violet-400/10 text-violet-300"
                    : "border-slate-700 text-slate-400 hover:text-slate-200"
                  }`}
              >
                {s.toLowerCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Submissions list */}
        {filtered.length === 0 ? (
          <div className="mt-6">
            <EmptyState
              title="No community submissions yet"
              description="Be the first to report a suspicious indicator using the form above."
            />
          </div>
        ) : (
          <div className="mt-6 space-y-3">
            {filtered.map((s: CommunitySubmission) => {
              const StatusIcon = STATUS_ICONS[s.status] ?? Clock;
              return (
                <div key={s.id} className="card p-5">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={STATUS_STYLES[s.status] ?? STATUS_STYLES.PENDING}>
                      <span className="inline-flex items-center gap-1">
                        <StatusIcon className="h-3 w-3" /> {s.status}
                      </span>
                    </Badge>
                    <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">
                      {s.indicator_type}
                    </Badge>
                    <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">
                      {s.threat_category}
                    </Badge>
                    <span className="ml-auto text-xs text-slate-500">{formatDate(s.created_at)}</span>
                  </div>
                  <p className="mt-3 break-all font-mono text-sm text-cyan-300">{s.indicator_value}</p>
                  <p className="mt-2 text-sm text-slate-300">{s.description}</p>
                  {s.evidence && <p className="mt-1 text-xs text-slate-500">Evidence: {s.evidence}</p>}
                  <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                    <span>source: {s.source_name}</span>
                    {s.review_notes && <span>review: {s.review_notes}</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

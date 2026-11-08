"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { Suspense } from "react";
import { ChevronLeft, FileSearch } from "lucide-react";
import { api } from "@/lib/api";
import { MODULE_LABELS, RISK_BANDS, formatDate } from "@/lib/format";
import { Badge, EvidenceCard, ErrorState, RiskGauge, SeverityBadge, Spinner } from "@/components/ui";
import type {
  DetectionResult,
  Finding,
  ScanIntelligenceResponse,
  ScanResponse,
} from "@/lib/types";

type TabKey = "overview" | "evidence" | "modules" | "findings" | "intelligence" | "recommendations";

const TABS: { key: TabKey; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "evidence", label: "Evidence" },
  { key: "modules", label: "Modules" },
  { key: "findings", label: "Findings" },
  { key: "intelligence", label: "Intelligence" },
  { key: "recommendations", label: "Recommendations" },
];

function ModuleCard({ name, data }: { name: string; data: Record<string, unknown> }) {
  const entries = Object.entries(data ?? {});
  return (
    <div className="card p-5">
      <h3 className="font-semibold text-cyan-300">{MODULE_LABELS[name] ?? name}</h3>
      {entries.length === 0 ? (
        <p className="mt-2 text-sm text-slate-500">No data recorded for this module.</p>
      ) : (
        <dl className="mt-3 space-y-1.5 text-sm">
          {entries
            .filter(([, v]) => v !== null && v !== undefined)
            .slice(0, 12)
            .map(([k, v]) => (
              <div key={k} className="flex flex-wrap justify-between gap-2">
                <dt className="text-slate-500">{k.replace(/_/g, " ")}</dt>
                <dd className="max-w-[60%] break-words text-right font-mono text-xs text-slate-200">
                  {typeof v === "object" ? JSON.stringify(v) : String(v)}
                </dd>
              </div>
            ))}
        </dl>
      )}
    </div>
  );
}

function ScanResultInner() {
  const params = useParams<{ scanId: string }>();
  const scanId = params.scanId;

  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [detection, setDetection] = useState<DetectionResult | null>(null);
  const [evidence, setEvidence] = useState<DetectionResult["evidence"]>([]);
  const [intel, setIntel] = useState<ScanIntelligenceResponse | null>(null);
  const [tab, setTab] = useState<TabKey>("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [scanRes, detectionRes, evidenceRes, intelRes] = await Promise.all([
        api.getScan(scanId),
        api.getScanDetection(scanId).catch(() => null),
        api.getScanEvidence(scanId).catch(() => null),
        api.getScanIntelligence(scanId).catch(() => null),
      ]);
      setScan(scanRes);
      setDetection(detectionRes?.detection ?? null);
      setEvidence(evidenceRes?.evidence ?? detectionRes?.detection?.evidence ?? []);
      setIntel(intelRes);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan.");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    const timer = setTimeout(() => void load(), 0);
    return () => clearTimeout(timer);
  }, [load]);

  if (loading) return <Spinner label="Loading scan report…" />;
  if (error || !scan)
    return (
      <div className="mx-auto max-w-3xl px-4 py-16">
        <ErrorState message={error ?? "Scan not found."} onRetry={load} />
      </div>
    );

  const band = RISK_BANDS[scan.threat_assessment.classification];
  const findings: Finding[] = scan.findings;
  const recommendations = scan.recommendations;

  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6">
      <Link href="/history" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-cyan-300">
        <ChevronLeft className="h-4 w-4" /> Back to history
      </Link>

      {/* Header */}
      <div className="card mt-4 p-6 sm:p-8">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-wider text-slate-500">Scan report</p>
            <h1 className="mt-1 break-all font-mono text-2xl font-bold text-white">{scan.target}</h1>
            <p className="mt-1 text-xs text-slate-500">
              Scan ID {scan.scan_id} · created {formatDate(scan.created_at)} · completed {formatDate(scan.completed_at)}
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              <Badge className={`${band.border} ${band.bg} ${band.color}`}>{band.label}</Badge>
              <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">
                Confidence: {scan.threat_assessment.confidence}
              </Badge>
              <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">
                Posture: {scan.threat_assessment.security_posture_score}/100
              </Badge>
              <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">
                Status: {scan.status}
              </Badge>
            </div>
          </div>
          <RiskGauge score={scan.threat_assessment.risk_score} size={150} />
        </div>
        {scan.threat_assessment.explanation && (
          <p className="mt-6 rounded-lg border border-slate-800/60 bg-slate-900/40 p-4 text-sm text-slate-300">
            {scan.threat_assessment.explanation}
          </p>
        )}
        <p className="mt-3 text-xs text-slate-500">
          Heuristic score — not a probability. No strong threat indicators observed in the completed checks does not
          guarantee the website is safe.
        </p>
      </div>

      {/* Tabs */}
      <div className="mt-6 flex flex-wrap gap-1.5">
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition-colors ${tab === t.key
                ? "bg-cyan-400/10 text-cyan-300"
                : "text-slate-400 hover:bg-slate-800/60 hover:text-white"
              }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="mt-4">
        {tab === "overview" && detection && (
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="card p-6">
              <h3 className="font-semibold text-white">Risk breakdown</h3>
              <p className="mt-1 text-sm text-slate-400">Score {detection.risk_score} · classification {detection.classification}</p>
              <ul className="mt-4 space-y-2">
                {detection.reasons.map((r, i) => (
                  <li key={i} className="flex gap-2 text-sm text-slate-300">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400" />
                    {r}
                  </li>
                ))}
              </ul>
            </div>
            <div className="card p-6">
              <h3 className="font-semibold text-white">Confidence</h3>
              <p className="mt-1 text-sm text-slate-400">
                {detection.confidence_score}/100 · {detection.confidence_level}
              </p>
              <div className="mt-4 grid grid-cols-3 gap-3 text-center">
                <div className="rounded-lg border-emerald-400/20 bg-emerald-400/5 p-3">
                  <p className="text-xl font-bold text-emerald-300">{detection.successful_checks}</p>
                  <p className="text-xs text-slate-500">successful</p>
                </div>
                <div className="rounded-lg border-rose-400/20 bg-rose-400/5 p-3">
                  <p className="text-xl font-bold text-rose-300">{detection.failed_checks}</p>
                  <p className="text-xs text-slate-500">failed</p>
                </div>
                <div className="rounded-lg border-violet-400/20 bg-violet-400/5 p-3">
                  <p className="text-xl font-bold text-violet-300">{detection.unavailable_providers}</p>
                  <p className="text-xs text-slate-500">unavailable</p>
                </div>
              </div>
              {detection.confidence_explanation && (
                <p className="mt-4 text-xs text-slate-400">{detection.confidence_explanation}</p>
              )}
            </div>
          </div>
        )}
        {tab === "overview" && !detection && (
          <div className="card p-8 text-center text-sm text-slate-400">
            No detection result stored for this scan.
          </div>
        )}

        {tab === "evidence" && (
          <div className="space-y-3">
            <p className="text-sm text-slate-500">
              {evidence.length} deduplicated evidence items
              {detection && detection.duplicates_removed > 0 && ` · ${detection.duplicates_removed} duplicates removed`}
            </p>
            {evidence.length === 0 ? (
              <div className="card p-8 text-center text-sm text-slate-400">No evidence recorded.</div>
            ) : (
              evidence.map((item, i) => <EvidenceCard key={`${item.id}-${i}`} item={item} />)
            )}
          </div>
        )}

        {tab === "modules" && (
          <div className="grid gap-4 sm:grid-cols-2">
            {Object.entries(scan.modules).map(([name, data]) => (
              <ModuleCard key={name} name={name} data={data} />
            ))}
          </div>
        )}

        {tab === "findings" && (
          <div className="space-y-3">
            {findings.length === 0 ? (
              <div className="card p-8 text-center text-sm text-slate-400">No findings recorded.</div>
            ) : (
              findings.map((f) => (
                <div key={f.id} className="card p-5">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <Badge className="border-slate-600/40 bg-slate-700/20 text-slate-300">{f.module}</Badge>
                    <span className="font-medium text-white">{f.title}</span>
                  </div>
                  <p className="mt-2 text-sm text-slate-300">{f.description}</p>
                  <p className="mt-2 font-mono text-xs text-slate-600">{f.id}</p>
                </div>
              ))
            )}
          </div>
        )}

        {tab === "intelligence" && (
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="card p-6">
              <h3 className="font-semibold text-white">Threat Intelligence</h3>
              {Object.keys(intel?.threat_intelligence ?? {}).length === 0 ? (
                <p className="mt-2 text-sm text-slate-500">No threat intelligence output recorded.</p>
              ) : (
                <pre className="mt-3 max-h-96 overflow-auto rounded-lg bg-slate-950/60 p-4 text-xs text-slate-300">
                  {JSON.stringify(intel?.threat_intelligence, null, 2)}
                </pre>
              )}
            </div>
            <div className="card p-6">
              <h3 className="font-semibold text-white">Domain Intelligence (RDAP)</h3>
              {Object.keys(intel?.domain_intelligence ?? {}).length === 0 ? (
                <p className="mt-2 text-sm text-slate-500">No RDAP output recorded.</p>
              ) : (
                <pre className="mt-3 max-h-96 overflow-auto rounded-lg bg-slate-950/60 p-4 text-xs text-slate-300">
                  {JSON.stringify(intel?.domain_intelligence, null, 2)}
                </pre>
              )}
            </div>
          </div>
        )}

        {tab === "recommendations" && (
          <div className="space-y-3">
            {recommendations.length === 0 ? (
              <div className="card p-8 text-center text-sm text-slate-400">No recommendations recorded.</div>
            ) : (
              recommendations.map((r, i) => (
                <div key={i} className="card flex items-start gap-3 p-4">
                  <FileSearch className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
                  <p className="text-sm text-slate-200">{r}</p>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ScanResultPage() {
  return (
    <Suspense fallback={<Spinner label="Loading scan report…" />}>
      <ScanResultInner />
    </Suspense>
  );
}

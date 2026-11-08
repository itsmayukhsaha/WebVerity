"use client";

import type { EvidenceItem, Finding, Severity } from "@/lib/types";
import { RISK_BANDS, SEVERITY_STYLES, riskBand } from "@/lib/format";
import { Loader2 } from "lucide-react";
import type { ReactNode } from "react";

/** Circular risk gauge (0–100) using pure SVG. */
export function RiskGauge({ score, size = 140 }: { score: number; size?: number }) {
  const band = riskBand(score);
  const style = RISK_BANDS[band];
  const stroke = 10;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - score / 100);

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(148,163,184,0.15)"
          strokeWidth={stroke}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth={stroke}
          strokeLinecap="round"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={style.color}
          style={{ transition: "stroke-dashoffset 0.8s ease" }}
        />
        <text
          x="50%"
          y="50%"
          dominantBaseline="central"
          textAnchor="middle"
          className={`fill-current ${style.color}`}
          style={{ fontSize: size / 3.2, fontWeight: 700, transform: "rotate(90deg)", transformOrigin: "center" }}
        >
          {score}
        </text>
      </svg>
      <span className={`text-sm font-semibold ${style.color}`}>{style.label}</span>
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Finding["severity"] | string }) {
  const cls = SEVERITY_STYLES[severity as Severity] ?? SEVERITY_STYLES.INFO;
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${cls}`}>{severity}</span>
  );
}

export function Badge({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${className}`}>{children}</span>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-slate-400">
      <Loader2 className="h-5 w-5 animate-spin text-cyan-400" />
      {label && <span>{label}</span>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="card flex flex-col items-center gap-4 p-10 text-center">
      <p className="text-rose-300">{message}</p>
      {onRetry && (
        <button className="btn-secondary" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, description }: { title: string; description?: string }) {
  return (
    <div className="card flex flex-col items-center gap-2 p-10 text-center">
      <p className="font-semibold text-slate-200">{title}</p>
      {description && <p className="text-sm text-slate-400">{description}</p>}
    </div>
  );
}

const CATEGORY_STYLES: Record<string, string> = {
  malicious_indicator: "bg-rose-500/10 text-rose-300 border-rose-500/30",
  suspicious: "bg-amber-400/10 text-amber-300 border-amber-400/30",
  security_weakness: "bg-sky-400/10 text-sky-300 border-sky-400/30",
  neutral: "bg-slate-400/10 text-slate-300 border-slate-400/30",
  unavailable: "bg-violet-400/10 text-violet-300 border-violet-400/30",
};

export function EvidenceCard({ item }: { item: EvidenceItem }) {
  const cls = CATEGORY_STYLES[item.category] ?? CATEGORY_STYLES.neutral;
  return (
    <div className="card p-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge className={cls}>{item.category.replace(/_/g, " ")}</Badge>
        <SeverityBadge severity={item.severity} />
        <span className="text-xs text-slate-500">source: {item.source}</span>
        {item.status && <span className="text-xs text-slate-500">status: {item.status}</span>}
      </div>
      <p className="mt-2 text-sm text-slate-200">{item.description}</p>
      <div className="mt-2 flex items-center justify-between text-xs text-slate-500">
        <span className="font-mono">{item.id}</span>
        <span>confidence {(item.confidence * 100).toFixed(0)}%</span>
      </div>
    </div>
  );
}

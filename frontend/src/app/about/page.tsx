import Link from "next/link";
import { BookOpen, Code2, Cpu, Database, Globe, Lock, Scale, ShieldCheck } from "lucide-react";

const STACK = [
  { icon: Cpu, label: "FastAPI + Uvicorn (ASGI)", detail: "Async pipeline orchestrating all analyzer modules" },
  { icon: Database, label: "SQLAlchemy 2.x", detail: "SQLite locally; PostgreSQL/Supabase compatible in production" },
  { icon: Globe, label: "Next.js + React + TypeScript", detail: "App Router frontend with Tailwind CSS" },
  { icon: Lock, label: "dnspython · cryptography · httpx", detail: "DNS resolution, X.509 validation, safe HTTP fetching" },
];

const SECURITY = [
  "Strict SSRF guard: private, loopback, link-local, multicast, and cloud-metadata addresses are rejected before any connection.",
  "DNS rebinding protection: connections are pinned to the validated IP while the original hostname is used for SNI and certificate validation.",
  "TLS verification against the system trust store on every handshake, for every redirect hop.",
  "URL redaction: sensitive query parameters are never persisted or sent to external intelligence providers.",
  "No fabricated evidence: unavailable providers and failed checks are reported honestly as UNAVAILABLE, never as clean results.",
];

export default function AboutPage() {
  return (
    <div className="glow-bg min-h-[calc(100vh-4rem-4.5rem)]">
      <div className="mx-auto max-w-4xl px-4 py-12 sm:px-6">
        <h1 className="text-3xl font-bold text-white">About Verity</h1>
        <p className="mt-3 text-slate-400">
          Verity (WebVerity) is an accessible, multi-layered cybersecurity platform that detects phishing
          infrastructure and evaluates website trustworthiness through deterministic feature extraction, DNS
          configuration analysis, cryptographic TLS certificate validation, HTTP security-header assessment,
          redirect-chain inspection, passive HTML content analysis, RDAP domain registration intelligence, external
          threat-intelligence feeds, and explainable rule-based risk scoring.
        </p>

        <div className="card mt-8 p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <ShieldCheck className="h-5 w-5 text-cyan-400" /> Why it exists
          </h2>
          <p className="mt-3 text-sm leading-relaxed text-slate-400">
            Phishing remains the primary initial access vector in modern cyberattacks. Modern threat actors leverage
            ephemeral cloud infrastructure, typosquatting domains, punycode homographs, and disposable TLS
            certificates to impersonate trusted institutions. Traditional blacklists suffer critical latency gaps,
            leaving users unprotected during the initial hours of a zero-day phishing campaign. Verity performs
            active, multi-layer verification immediately upon URL submission instead of relying on stale reputation
            lists.
          </p>
        </div>

        <div className="card mt-6 p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <Cpu className="h-5 w-5 text-blue-400" /> Technology
          </h2>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            {STACK.map((s) => (
              <div key={s.label} className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-4">
                <p className="flex items-center gap-2 font-medium text-slate-100">
                  <s.icon className="h-4 w-4 text-cyan-400" /> {s.label}
                </p>
                <p className="mt-1 text-xs text-slate-500">{s.detail}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="card mt-6 p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <Lock className="h-5 w-5 text-violet-400" /> Security invariants
          </h2>
          <ul className="mt-4 space-y-3 text-sm text-slate-400">
            {SECURITY.map((item) => (
              <li key={item} className="flex gap-2.5">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-violet-400" />
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="card mt-6 p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <Scale className="h-5 w-5 text-emerald-400" /> Scoring model
          </h2>
          <div className="mt-4 space-y-3 text-sm text-slate-400">
            <p>
              <span className="font-medium text-slate-200">Threat Risk (0–100):</span> phishing/malicious likelihood
              with bands LOW (0–24), MODERATE (25–49), HIGH (50–74), CRITICAL (75–100). Verified threat-feed matches
              dominate weak heuristics; configuration weaknesses are excluded from threat evidence.
            </p>
            <p>
              <span className="font-medium text-slate-200">Security Posture (0–100):</span> configuration quality
              (headers, cookies, TLS hygiene). A legitimate site with a missing CSP stays LOW-threat with a reduced
              posture.
            </p>
            <p>
              <span className="font-medium text-slate-200">Confidence (LOW/MEDIUM/HIGH):</span> evidence completeness
              × intelligence verification — independent of risk level.
            </p>
            <p>
              All scores are heuristic (<code className="font-mono text-xs text-cyan-300">is_probability: false</code>).
              A LOW rating always carries the disclaimer: no strong threat indicators observed in the completed
              checks — this does not guarantee that the website is safe.
            </p>
          </div>
        </div>

        <div className="card mt-6 p-6">
          <h2 className="flex items-center gap-2 text-lg font-semibold text-white">
            <BookOpen className="h-5 w-5 text-amber-400" /> Disclosures
          </h2>
          <p className="mt-3 text-sm text-slate-400">
            All external libraries are free and open-source software under permissive licenses (MIT, Apache-2.0, BSD).
            abuse.ch URLhaus data is used per its public API terms; queries are redacted (no query strings sent).
            PhishTank requires an application key and is disabled without one. No fabricated intelligence is ever
            produced — unavailable sources return honest UNAVAILABLE/SKIPPED states.
          </p>
        </div>

        <div className="mt-10 flex flex-col items-center gap-3 text-center">
          <Code2 className="h-6 w-6 text-cyan-400" />
          <p className="text-sm text-slate-500">
            Explore the live API documentation at{" "}
            <a
              href={`${process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000"}/docs`}
              target="_blank"
              rel="noreferrer"
              className="text-cyan-400"
            >
              /docs
            </a>{" "}
            or start a{" "}
            <Link href="/scan" className="text-cyan-400">
              new scan
            </Link>
            .
          </p>
        </div>
      </div>
    </div>
  );
}

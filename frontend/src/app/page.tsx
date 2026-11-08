import Link from "next/link";
import {
  Activity,
  ArrowRight,
  Binary,
  Fingerprint,
  Globe,
  Lock,
  Network,
  Radar,
  ShieldCheck,
  Siren,
} from "lucide-react";

const FEATURES = [
  {
    icon: Binary,
    title: "URL Structural Analysis",
    description:
      "Hostname entropy, subdomain depth, suspicious keywords, punycode homographs, embedded credentials, and obfuscated encodings.",
  },
  {
    icon: Network,
    title: "DNS Infrastructure",
    description:
      "IPv4/IPv6, CNAME chains, MX presence, and nameservers resolved and validated before any connection is made.",
  },
  {
    icon: Lock,
    title: "Cryptographic TLS Inspection",
    description:
      "Active handshake with SNI against a pinned public IP — trust chains, validity dates, SANs, cipher suites, and key strength.",
  },
  {
    icon: ShieldCheck,
    title: "Hardened SSRF Defenses",
    description:
      "Strict public-IP validation on every request and redirect hop blocks private networks, DNS rebinding, and cloud metadata access.",
  },
  {
    icon: Radar,
    title: "Threat Intelligence",
    description:
      "abuse.ch URLhaus and optional PhishTank lookups with redacted indicators and honest UNAVAILABLE states — never fabricated.",
  },
  {
    icon: Activity,
    title: "Explainable Dual Scoring",
    description:
      "Separate THREAT RISK and SECURITY POSTURE scores plus an independent confidence rating with a full evidence breakdown.",
  },
];

const ML_POINTS = [
  {
    icon: Fingerprint,
    title: "Weighted rule features",
    description:
      "Every finding carries an explicit weight from a published rules table — the score breakdown shows exactly how much each contributed.",
  },
  {
    icon: Radar,
    title: "Evidence correlation",
    description:
      "Findings from all modules are deduplicated and bucketed into malicious, suspicious, weakness, neutral, and unavailable evidence before scoring.",
  },
  {
    icon: Activity,
    title: "Verified-intel precedence",
    description:
      "Confirmed threat-feed matches dominate weak heuristics, and insufficient evidence caps escalation — no false amplification.",
  },
];

const PIPELINE = [
  "URL validation & SSRF guard",
  "URL, DNS & RDAP analysis",
  "TLS handshake (pinned IP)",
  "Safe HTTP fetch & headers",
  "Redirect & content analysis",
  "Threat intelligence matching",
  "Evidence correlation",
  "Explainable risk scoring",
];

export default function LandingPage() {
  return (
    <div className="glow-bg">
      {/* Hero */}
      <section className="mx-auto max-w-7xl px-4 pb-20 pt-20 sm:px-6 lg:pt-28">
        <div className="animate-fade-up flex flex-col items-center text-center">
          <span className="mb-6 inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/5 px-4 py-1.5 text-sm text-cyan-300">
            <span className="h-2 w-2 animate-pulse-dot rounded-full bg-cyan-400" />
            Multi-layered phishing detection engine
          </span>
          <h1 className="max-w-3xl text-4xl font-bold leading-tight tracking-tight text-white sm:text-5xl lg:text-6xl">
            Know if a website is <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-violet-500 bg-clip-text text-transparent">safe — and why</span>
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-slate-400">
            Verity evaluates website trust through deterministic feature extraction, DNS configuration analysis,
            cryptographic TLS validation, HTTP security assessment, redirect-chain inspection, RDAP domain
            intelligence, and external threat-intelligence feeds — with fully explainable risk scoring.
          </p>
          <div className="mt-10 flex flex-col gap-3 sm:flex-row">
            <Link href="/scan" className="btn-primary">
              Scan a website
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/dashboard" className="btn-secondary">
              Open dashboard
            </Link>
          </div>
          <div className="mt-14 flex flex-wrap items-center justify-center gap-x-8 gap-y-3 text-sm text-slate-500">
            <span className="flex items-center gap-2"><Fingerprint className="h-4 w-4 text-cyan-400" /> 8 analyzer modules</span>
            <span className="flex items-center gap-2"><Siren className="h-4 w-4 text-violet-400" /> Verified threat feeds</span>
            <span className="flex items-center gap-2"><Globe className="h-4 w-4 text-blue-400" /> SSRF-hardened by design</span>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="mx-auto max-w-7xl px-4 pb-24 sm:px-6">
        <h2 className="text-center text-3xl font-bold text-white">Detection layers, not blacklists</h2>
        <p className="mx-auto mt-3 max-w-2xl text-center text-slate-400">
          Traditional blacklists suffer critical latency gaps during zero-day phishing campaigns. Verity performs
          active, multi-layer verification immediately upon URL submission.
        </p>
        <div className="mt-12 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <div key={f.title} className="card card-hover p-6">
              <f.icon className="h-8 w-8 text-cyan-400" />
              <h3 className="mt-4 font-semibold text-white">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{f.description}</p>
              <Link href="/scan" className="mt-3 inline-flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300">
                Try it now <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Explainable detection / ML-style scoring */}
      <section className="mx-auto max-w-7xl px-4 pb-24 sm:px-6">
        <h2 className="text-center text-3xl font-bold text-white">Explainable detection, not a black box</h2>
        <p className="mx-auto mt-3 max-w-2xl text-center text-slate-400">
          Verity&apos;s detection engine combines weighted rule features with evidence correlation and
          independent confidence assessment. Every score ships with its reasons — model-style outputs are
          clearly labeled as heuristic (never a calibrated probability).
        </p>
        <div className="mt-12 grid gap-5 sm:grid-cols-3">
          {ML_POINTS.map((f) => (
            <div key={f.title} className="card card-hover p-6">
              <f.icon className="h-8 w-8 text-violet-400" />
              <h3 className="mt-4 font-semibold text-white">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-400">{f.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Pipeline */}
      <section className="mx-auto max-w-7xl px-4 pb-24 sm:px-6">
        <div className="card p-8 lg:p-12">
          <h2 className="text-2xl font-bold text-white">The assessment pipeline</h2>
          <p className="mt-2 text-slate-400">
            Every URL submission runs through a deterministic, failure-isolated pipeline. Missing or unavailable
            checks are reported honestly — never treated as phishing proof.
          </p>
          <ol className="mt-8 grid gap-3 sm:grid-cols-2">
            {PIPELINE.map((step, i) => (
              <li key={step} className="flex items-center gap-3 rounded-lg border border-slate-800/60 bg-slate-900/30 px-4 py-3">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-500/20 to-blue-600/20 text-xs font-bold text-cyan-300">
                  {i + 1}
                </span>
                <span className="text-sm text-slate-200">{step}</span>
              </li>
            ))}
          </ol>
          <div className="mt-8 rounded-lg border border-amber-400/20 bg-amber-400/5 p-4 text-sm text-amber-200/90">
            All risk scores are heuristic ({`is_probability: false`}). A LOW rating means no strong threat indicators
            were observed in the completed checks — it does not guarantee that a website is safe.
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="mx-auto max-w-7xl px-4 pb-24 sm:px-6">
        <div className="card flex flex-col items-center gap-6 bg-gradient-to-br from-cyan-500/10 via-blue-600/5 to-violet-600/10 p-12 text-center">
          <h2 className="text-3xl font-bold text-white">Run your first assessment</h2>
          <p className="max-w-xl text-slate-400">
            Submit any public URL and receive a full report: risk score, security posture, correlated evidence,
            intelligence matches, and actionable recommendations.
          </p>
          <Link href="/scan" className="btn-primary">
            Start scanning
            <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </section>
    </div>
  );
}

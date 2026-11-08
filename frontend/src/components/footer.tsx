import Link from "next/link";
import { ShieldCheck } from "lucide-react";

export function Footer() {
  return (
    <footer className="border-t border-slate-800/60 py-8">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 text-sm text-slate-500 sm:flex-row sm:px-6">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-cyan-400" />
          <span>Verity — Intelligent Phishing Detection &amp; Website Trust Assessment</span>
        </div>
        <div className="flex items-center gap-5">
          <Link href="/about" className="hover:text-slate-300">
            About
          </Link>
          <Link href="/settings" className="hover:text-slate-300">
            Settings
          </Link>
          <a
            href={`${process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000"}/docs`}
            target="_blank"
            rel="noreferrer"
            className="hover:text-slate-300"
          >
            API Docs
          </a>
        </div>
      </div>
      <p className="mx-auto mt-4 max-w-7xl px-4 text-xs text-slate-600 sm:px-6">
        Scores are heuristic and not probabilities. Absence of threat indicators does not guarantee a website is safe.
      </p>
    </footer>
  );
}

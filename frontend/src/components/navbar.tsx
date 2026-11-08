"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Suspense, useState } from "react";
import { Menu, ScanSearch, ShieldCheck, X } from "lucide-react";

const NAV_LINKS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/scan", label: "Scan" },
  { href: "/history", label: "History" },
  { href: "/intelligence", label: "Threat Intel" },
  { href: "/community", label: "Community" },
  { href: "/analytics", label: "Analytics" },
  { href: "/admin", label: "Admin" },
  { href: "/about", label: "About" },
];

function NavbarInner() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/60 bg-[#050b18]/85 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5" onClick={() => setOpen(false)}>
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 to-blue-600">
            <ShieldCheck className="h-5 w-5 text-[#04101d]" />
          </span>
          <span className="text-lg font-bold tracking-tight text-white">
            Verity
            <span className="ml-2 hidden text-xs font-medium text-slate-500 sm:inline">WebVerity Platform</span>
          </span>
        </Link>

        <nav className="hidden items-center gap-1 md:flex">
          {NAV_LINKS.map((link) => {
            const active = pathname === link.href || pathname.startsWith(`${link.href}/`);
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`rounded-lg px-3 py-2 text-sm font-medium transition-colors ${active ? "bg-cyan-400/10 text-cyan-300" : "text-slate-300 hover:bg-slate-800/60 hover:text-white"
                  }`}
              >
                {link.label}
              </Link>
            );
          })}
          <Link href="/scan" className="btn-primary ml-2 text-sm">
            <ScanSearch className="h-4 w-4" />
            New Scan
          </Link>
        </nav>

        <button
          className="rounded-lg p-2 text-slate-300 md:hidden"
          onClick={() => setOpen((v) => !v)}
          aria-label="Toggle navigation"
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>

      {open && (
        <nav className="flex flex-col gap-1 border-t border-slate-800/60 px-4 pb-4 pt-2 md:hidden">
          {NAV_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setOpen(false)}
              className={`rounded-lg px-3 py-2 text-sm font-medium ${pathname === link.href ? "bg-cyan-400/10 text-cyan-300" : "text-slate-300"
                }`}
            >
              {link.label}
            </Link>
          ))}
          <Link href="/scan" onClick={() => setOpen(false)} className="btn-primary mt-2 text-sm">
            <ScanSearch className="h-4 w-4" />
            New Scan
          </Link>
        </nav>
      )}
    </header>
  );
}

export function Navbar() {
  return (
    <Suspense fallback={<div className="h-16 border-b border-slate-800/60 bg-[#050b18]" />}>
      <NavbarInner />
    </Suspense>
  );
}


import type { Metadata } from "next";
import { Navbar } from "@/components/navbar";
import { Footer } from "@/components/footer";
import "./globals.css";

// Fonts are intentionally NOT loaded from Google Fonts here.
// next/font/google downloads fonts at build time and can fail behind proxies or
// without network access ("Can't resolve
// '@vercel/turbopack-next/internal/font/google/font'"). The design instead uses
// a self-contained system-font stack defined in globals.css that closely matches
// Geist's geometric sans style, so local startup never depends on the network.

export const metadata: Metadata = {
  title: {

    default: "Verity — Intelligent Phishing Detection & Website Trust Assessment",
    template: "%s | Verity",
  },
  description:
    "Multi-layered phishing detection and website trust assessment: URL analysis, DNS, TLS, HTTP security, threat intelligence, and explainable risk scoring.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col">
        <Navbar />
        <main className="flex-1">{children}</main>
        <Footer />
      </body>
    </html>
  );
}

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Veritor — Supply Chain Integrity Analyzer",
  description:
    "Autonomous package vs source integrity verification engine. Inspects diffs, static AST security findings, Sigstore provenance, and AI explanations.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}

"use client";

import React from "react";
import {
  ShieldCheck,
  GitCompare,
  FileCode2,
  Sparkles,
  Lock,
  ArrowRight,
} from "lucide-react";
import { Ecosystem } from "../lib/types";

interface LandingHeroProps {
  onSelectSample: (ecosystem: Ecosystem, name: string, version: string) => void;
}

export function LandingHero({ onSelectSample }: LandingHeroProps) {
  const samplePackages: { ecosystem: Ecosystem; name: string; version: string; tag: string }[] = [
    {
      ecosystem: "npm",
      name: "left-pad",
      version: "1.3.0",
      tag: "Authentic & Clean",
    },
    {
      ecosystem: "npm",
      name: "chalk",
      version: "5.3.0",
      tag: "ESM Bundled",
    },
    {
      ecosystem: "npm",
      name: "express",
      version: "4.19.2",
      tag: "Popular Library",
    },
    {
      ecosystem: "npm",
      name: "event-stream",
      version: "3.3.6",
      tag: "Historical Supply Chain Incident",
    },
  ];

  return (
    <div className="relative py-8 md:py-12 border-b border-slate-800/80 overflow-hidden">
      {/* Background glow effects */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute top-1/3 left-1/4 w-64 h-64 bg-cyan-500/5 rounded-full blur-2xl pointer-events-none" />

      <div className="max-w-4xl mx-auto text-center px-4 relative z-10">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-700 text-xs font-mono text-emerald-400 mb-6">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Autonomous Supply Chain Verification Engine</span>
        </div>

        <h1 className="text-3xl sm:text-5xl font-extrabold text-white tracking-tight mb-4">
          Verify Published Packages Against{" "}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400">
            Source Code
          </span>
        </h1>

        <p className="text-base sm:text-lg text-slate-400 max-w-2xl mx-auto mb-8 leading-relaxed">
          Unmask hidden payloads, unauthorized artifacts, and unverified builds before installing.
          Combines git source diffing, AST security analysis, Sigstore provenance, and local AI reasoning.
        </p>

        {/* Feature Cards Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-left mb-8">
          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
            <div className="p-2 rounded bg-emerald-500/10 text-emerald-400 w-fit mb-2">
              <GitCompare className="w-4 h-4" />
            </div>
            <h2 className="text-sm font-semibold text-slate-200">Source Diffing</h2>
            <p className="text-xs text-slate-400 mt-1">Exact git tree vs registry tarball comparison.</p>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
            <div className="p-2 rounded bg-cyan-500/10 text-cyan-400 w-fit mb-2">
              <FileCode2 className="w-4 h-4" />
            </div>
            <h2 className="text-sm font-semibold text-slate-200">AST Analysis</h2>
            <p className="text-xs text-slate-400 mt-1">Tree-sitter static scan for eval, exec, and lifecycle abuse.</p>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
            <div className="p-2 rounded bg-amber-500/10 text-amber-400 w-fit mb-2">
              <Lock className="w-4 h-4" />
            </div>
            <h2 className="text-sm font-semibold text-slate-200">Provenance</h2>
            <p className="text-xs text-slate-400 mt-1">Sigstore &amp; GitHub Actions cryptographic verification.</p>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-colors">
            <div className="p-2 rounded bg-violet-500/10 text-violet-400 w-fit mb-2">
              <Sparkles className="w-4 h-4" />
            </div>
            <h2 className="text-sm font-semibold text-slate-200">AI Deep Reasoner</h2>
            <p className="text-xs text-slate-400 mt-1">Local Ollama reasoning on diffs without hallucination.</p>
          </div>
        </div>

        {/* Quick Sample Selector */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-2 text-xs">
          <span className="text-slate-500 font-mono">Quick scan demo:</span>
          <div className="flex flex-wrap items-center justify-center gap-2">
            {samplePackages.map((pkg) => (
              <button
                key={`${pkg.ecosystem}-${pkg.name}-${pkg.version}`}
                onClick={() => onSelectSample(pkg.ecosystem, pkg.name, pkg.version)}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-slate-800/90 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-200 font-mono transition-all group"
              >
                <span>{pkg.name}@{pkg.version}</span>
                <span className="text-[10px] text-slate-400">({pkg.tag})</span>
                <ArrowRight className="w-3 h-3 text-slate-400 group-hover:text-emerald-400 group-hover:translate-x-0.5 transition-all" />
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

"use client";

import React from "react";
import {
  CheckCircle2,
  CircleDashed,
  AlertOctagon,
  Clock,
  Sparkles,
  GitCompare,
  ShieldAlert,
  Lock,
  Layers,
} from "lucide-react";
import { ScanStage, ScanStatusResponse } from "../lib/types";

interface ProgressTrackerProps {
  status: ScanStatusResponse;
  onRetry?: () => void;
}

const STAGES_ORDER: { key: ScanStage; label: string; icon: React.ElementType }[] = [
  { key: "fetching_metadata", label: "Registry Metadata", icon: Clock },
  { key: "downloading_artifact", label: "Download Tarball", icon: Layers },
  { key: "resolving_source", label: "Resolve Source Git", icon: GitCompare },
  { key: "extracting_package", label: "Extract Package", icon: Layers },
  { key: "downloading_source", label: "Fetch Git Tree", icon: GitCompare },
  { key: "comparing", label: "Differential Engine", icon: GitCompare },
  { key: "security_scanning", label: "AST Security Walk", icon: ShieldAlert },
  { key: "checking_provenance", label: "Sigstore Provenance", icon: Lock },
  { key: "scoring_risk", label: "Deterministic Scoring", icon: Layers },
  { key: "ai_investigation", label: "AI Reasoning", icon: Sparkles },
  { key: "completed", label: "Integrity Verified", icon: CheckCircle2 },
];

export function ProgressTracker({ status, onRetry }: ProgressTrackerProps) {
  const currentStageIndex = STAGES_ORDER.findIndex((s) => s.key === status.stage);
  const isFailed = status.status === "failed";
  const isCompleted = status.status === "completed";

  return (
    <div className="w-full max-w-3xl mx-auto my-6 p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-2xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              {status.ecosystem}
            </span>
            <span className="text-base sm:text-lg font-mono font-bold text-slate-100">
              {status.package_name}@{status.version}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Scan ID: {status.scan_id}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isFailed ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-rose-500/20 border border-rose-500/40 text-rose-300 text-xs font-mono font-medium">
              <AlertOctagon className="w-4 h-4 text-rose-400" />
              FAILED
            </span>
          ) : isCompleted ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-mono font-medium">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              COMPLETED
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-medium animate-pulse">
              <CircleDashed className="w-4 h-4 text-cyan-400 animate-spin" />
              ANALYZING
            </span>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-300">{status.message || "Running pipeline stages..."}</span>
          <span className="text-emerald-400 font-semibold">{status.progress_percent}%</span>
        </div>
        <div className="w-full h-2 rounded-full bg-slate-950 overflow-hidden border border-slate-800">
          <div
            className={`h-full transition-all duration-300 ease-out rounded-full ${
              isFailed
                ? "bg-rose-500"
                : isCompleted
                ? "bg-emerald-500"
                : "bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-400"
            }`}
            style={{ width: `${Math.max(5, Math.min(100, status.progress_percent))}%` }}
          />
        </div>
      </div>

      {/* Error Banner if Failed */}
      {isFailed && (
        <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-200 text-xs font-mono space-y-2">
          <div className="flex items-center gap-2 font-bold text-rose-400">
            <AlertOctagon className="w-4 h-4" />
            <span>Analysis Interrupted</span>
          </div>
          <p className="text-slate-300">{status.error || "The scan encountered an unexpected error."}</p>
          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-2 inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-rose-600/30 hover:bg-rose-600/50 border border-rose-500/40 text-rose-200 font-mono text-xs transition-colors"
            >
              Retry Scan
            </button>
          )}
        </div>
      )}

      {/* Pipeline Stage Steps */}
      <div className="pt-2">
        <h4 className="text-xs uppercase tracking-wider font-mono text-slate-400 mb-3">
          Verification Pipeline Stages
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-xs font-mono">
          {STAGES_ORDER.map((stage, idx) => {
            const Icon = stage.icon;
            const isStageComplete = isCompleted || (currentStageIndex > idx);
            const isStageCurrent = !isCompleted && !isFailed && (currentStageIndex === idx || (currentStageIndex === -1 && idx === 0));

            return (
              <div
                key={stage.key}
                className={`flex items-center gap-2.5 p-2 rounded-lg border transition-all ${
                  isStageComplete
                    ? "bg-slate-950/40 border-slate-800 text-slate-300"
                    : isStageCurrent
                    ? "bg-slate-800/80 border-cyan-500/40 text-cyan-200 shadow-sm"
                    : "bg-slate-950/20 border-slate-900 text-slate-600"
                }`}
              >
                {isStageComplete ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : isStageCurrent ? (
                  <CircleDashed className="w-4 h-4 text-cyan-400 animate-spin shrink-0" />
                ) : (
                  <Icon className="w-4 h-4 text-slate-600 shrink-0" />
                )}
                <span className="truncate">{stage.label}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

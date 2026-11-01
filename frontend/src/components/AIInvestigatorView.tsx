"use client";

import React from "react";
import {
  Sparkles,
  Cpu,
  ShieldCheck,
} from "lucide-react";
import { AIInvestigationResult } from "../lib/types";

interface AIInvestigatorViewProps {
  ai: AIInvestigationResult | null | undefined;
  packageName: string;
  version: string;
}

export function AIInvestigatorView({
  ai,
  packageName,
  version,
}: AIInvestigatorViewProps) {
  const isEnabled = ai?.enabled ?? false;

  return (
    <div className="w-full space-y-6 font-mono text-xs">
      {/* Header Card */}
      <div className="p-6 rounded-xl bg-violet-500/10 border border-violet-500/30 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-violet-500/20 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-slate-950 border border-violet-500/40 text-violet-400">
              <Sparkles className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm sm:text-base font-bold text-slate-100">
                  AI Deep Supply Chain Reasoning
                </span>
                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-bold border ${
                    isEnabled
                      ? "bg-violet-500/20 text-violet-300 border-violet-500/40"
                      : "bg-slate-800 text-slate-400 border-slate-700"
                  }`}
                >
                  {isEnabled ? "ACTIVE" : "STANDBY"}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Local LLM ({ai?.model || "qwen2.5-coder:7b"}) analyzing differential AST evidence
              </p>
            </div>
          </div>

          <div className="text-right text-slate-400">
            <span>{packageName}@{version}</span>
          </div>
        </div>

        {/* Notice on AI Non-Overriding Rule */}
        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 flex items-start gap-2.5">
          <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
          <p className="text-[11px] leading-relaxed">
            <strong className="text-emerald-400">Deterministic Safety Guarantee: </strong>
            Veritor enforces strict isolation between deterministic risk scoring and AI explanation.
            The AI model cannot hallucinate evidence, override hard security floors, or lower calculated risk scores.
          </p>
        </div>
      </div>

      {/* Triage Summary */}
      {ai?.triage_summary && (
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
          <h3 className="text-slate-200 font-bold text-sm flex items-center gap-2">
            <Cpu className="w-4 h-4 text-violet-400" />
            Executive Synthesis
          </h3>
          <p className="text-slate-300 text-xs leading-relaxed p-3 rounded bg-slate-950 border border-slate-800">
            {ai.triage_summary}
          </p>
        </div>
      )}

      {/* Individual AI Findings Explanations */}
      {ai?.explanations && ai.explanations.length > 0 ? (
        <div className="space-y-4">
          <h3 className="text-slate-200 font-bold text-sm">
            Detailed Behavioral Corroboration ({ai.explanations.length})
          </h3>

          <div className="space-y-3">
            {ai.explanations.map((exp, idx) => (
              <div
                key={idx}
                className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 shadow-md"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-violet-300 text-xs">
                      {exp.finding_rule_id}
                    </span>
                    <span className="text-slate-400 text-xs truncate max-w-sm">
                      {exp.file_path}
                    </span>
                  </div>

                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-bold border ${
                      exp.false_positive_likelihood === "HIGH"
                        ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                        : exp.false_positive_likelihood === "MEDIUM"
                        ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                        : "bg-rose-500/20 text-rose-300 border-rose-500/40"
                    }`}
                  >
                    FP Likelihood: {exp.false_positive_likelihood}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div className="text-slate-300 font-semibold">{exp.assessment}</div>
                  <p className="text-slate-400 leading-relaxed">{exp.reason}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="p-12 rounded-xl bg-slate-900/90 border border-slate-800 text-center space-y-2">
          <Sparkles className="w-8 h-8 mx-auto text-violet-400" />
          <h4 className="text-slate-200 font-bold text-sm">No Behavioral Anomalies Flagged</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            {isEnabled
              ? "The AI investigator found no ambiguous patterns requiring deep contextual reasoning."
              : "AI analysis was skipped or ran in deterministic-only mode."}
          </p>
        </div>
      )}
    </div>
  );
}

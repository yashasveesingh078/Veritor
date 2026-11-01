"use client";

import React, { useState, useMemo } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  Sparkles,
  ExternalLink,
  Code2,
  CheckCircle2,
  Filter,
} from "lucide-react";
import {
  AIExplanationItem,
  AnalysisGap,
  FindingSeverity,
  SecurityFinding,
} from "../lib/types";

interface FindingsViewerProps {
  findings: SecurityFinding[];
  gaps?: AnalysisGap[];
  aiExplanations?: AIExplanationItem[];
  onSelectFile?: (filePath: string) => void;
}

export function FindingsViewer({
  findings,
  gaps = [],
  aiExplanations = [],
  onSelectFile,
}: FindingsViewerProps) {
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  const filteredFindings = useMemo(() => {
    if (severityFilter === "ALL") return findings;
    return findings.filter((f) => f.severity === severityFilter);
  }, [findings, severityFilter]);

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    findings.forEach((f) => {
      if (counts[f.severity] !== undefined) {
        counts[f.severity]++;
      }
    });
    return counts;
  }, [findings]);

  const getSeverityBadge = (severity: FindingSeverity) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "HIGH":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      case "LOW":
        return "bg-blue-500/20 text-blue-300 border-blue-500/40";
      case "INFO":
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  return (
    <div className="w-full space-y-6">
      {/* Top Severity Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-slate-500 mr-1 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Severity:
          </span>
          <button
            onClick={() => setSeverityFilter("ALL")}
            className={`px-2.5 py-1 rounded transition-colors ${
              severityFilter === "ALL"
                ? "bg-slate-700 text-slate-100 font-bold border border-slate-600"
                : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            All ({findings.length})
          </button>
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as FindingSeverity[]).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded transition-colors ${
                severityFilter === sev
                  ? "bg-slate-700 text-slate-100 font-bold border border-slate-600"
                  : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
              }`}
            >
              {sev} ({severityCounts[sev] || 0})
            </button>
          ))}
        </div>

        <div className="text-slate-400">
          Showing {filteredFindings.length} of {findings.length} findings
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length > 0 ? (
        <div className="space-y-4">
          {filteredFindings.map((finding, idx) => {
            const aiMatch = aiExplanations.find(
              (exp) => exp.finding_rule_id === finding.rule_id || exp.file_path === finding.path
            );

            return (
              <div
                key={idx}
                className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3.5 font-mono shadow-md hover:border-slate-700 transition-colors"
              >
                {/* Header: Rule ID, Severity, File Location */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[11px] font-bold px-2 py-0.5 rounded border ${getSeverityBadge(
                        finding.severity
                      )}`}
                    >
                      {finding.severity}
                    </span>
                    <span className="font-bold text-slate-200 text-sm">
                      {finding.rule_id}
                    </span>
                    <span className="text-[11px] text-slate-500">
                      Confidence: {(finding.confidence * 100).toFixed(0)}%
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-slate-400 truncate max-w-xs sm:max-w-md">
                      {finding.path}:{finding.line}
                    </span>
                    {onSelectFile && (
                      <button
                        onClick={() => onSelectFile(finding.path)}
                        className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 transition-colors"
                        title="View file diff"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span className="text-[11px]">View Diff</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Explanation */}
                <div className="text-xs text-slate-300 leading-relaxed">
                  <p>{finding.explanation}</p>
                </div>

                {/* Code Evidence Snippet */}
                {finding.evidence && (
                  <div className="rounded-lg bg-slate-950 border border-slate-800 p-3 overflow-x-auto text-xs">
                    <div className="flex items-center gap-1.5 text-slate-500 text-[10px] uppercase mb-1.5 font-semibold">
                      <Code2 className="w-3 h-3 text-slate-400" />
                      <span>Code Evidence (Line {finding.line})</span>
                    </div>
                    <pre className="text-emerald-300/90 whitespace-pre font-mono text-[11px]">
                      {finding.evidence}
                    </pre>
                  </div>
                )}

                {/* Recommended Remediation Action */}
                {finding.recommended_action && (
                  <div className="p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20 text-xs text-emerald-300/90 flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-emerald-300 font-semibold">Recommended Action: </strong>
                      <span>{finding.recommended_action}</span>
                    </div>
                  </div>
                )}

                {/* AI Behavioral Correlation (if available) */}
                {aiMatch && (
                  <div className="p-3.5 rounded-lg bg-violet-500/10 border border-violet-500/30 text-xs space-y-1.5 text-violet-200">
                    <div className="flex items-center gap-1.5 text-violet-400 font-bold">
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>AI Reasoning Analysis</span>
                      <span className="text-[10px] ml-auto font-normal px-2 py-0.5 rounded bg-violet-500/20 border border-violet-500/40">
                        FP Likelihood: {aiMatch.false_positive_likelihood}
                      </span>
                    </div>
                    <p className="text-slate-300">{aiMatch.reason}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="p-12 rounded-xl bg-slate-900/90 border border-slate-800 text-center font-mono space-y-2">
          <ShieldAlert className="w-8 h-8 mx-auto text-emerald-400" />
          <h4 className="text-slate-200 font-bold text-sm">No Security Findings Detected</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Static AST analysis found zero unauthorized eval, exec, network calls, or malicious lifecycle hooks matching current criteria.
          </p>
        </div>
      )}

      {/* Analysis Gaps Section */}
      {gaps.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-amber-400 font-bold">
            <AlertTriangle className="w-4 h-4" />
            <span>Analysis Gaps &amp; Scanner Limitations ({gaps.length})</span>
          </div>
          <p className="text-slate-400">
            Certain files were skipped or partially parsed to respect system boundaries:
          </p>
          <div className="space-y-2">
            {gaps.map((gap, i) => (
              <div key={i} className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-start gap-2">
                <span className="text-slate-500">•</span>
                <span className="text-slate-300 font-semibold">{gap.path}:</span>
                <span className="text-slate-400">{gap.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

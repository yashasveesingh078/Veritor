"use client";

import React from "react";
import {
  ShieldCheck,
  Download,
  Clock,
  Layers,
  Sparkles,
  GitBranch,
  CheckCircle2,
  AlertOctagon,
} from "lucide-react";
import { RiskLevel, ScanReportResponse } from "../lib/types";

interface ReportDashboardProps {
  report: ScanReportResponse;
  activeReportTab: "overview" | "files" | "findings" | "provenance" | "ai";
  setActiveReportTab: (tab: "overview" | "files" | "findings" | "provenance" | "ai") => void;
}

export function ReportDashboard({
  report,
  activeReportTab,
  setActiveReportTab,
}: ReportDashboardProps) {
  const risk = report.risk;
  const security = report.security;
  const comparison = report.comparison;
  const provenance = report.provenance;

  const score = risk?.score ?? 0;
  const level: RiskLevel = risk?.level ?? "LOW";

  // Color mappings based on risk level
  const getRiskColor = (lvl: RiskLevel) => {
    switch (lvl) {
      case "CRITICAL":
        return {
          text: "text-rose-400",
          bg: "bg-rose-500/10",
          border: "border-rose-500/30",
          badge: "bg-rose-500/20 text-rose-300 border-rose-500/40",
          gauge: "#f43f5e",
        };
      case "HIGH":
        return {
          text: "text-orange-400",
          bg: "bg-orange-500/10",
          border: "border-orange-500/30",
          badge: "bg-orange-500/20 text-orange-300 border-orange-500/40",
          gauge: "#f97316",
        };
      case "MEDIUM":
        return {
          text: "text-amber-400",
          bg: "bg-amber-500/10",
          border: "border-amber-500/30",
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          gauge: "#f59e0b",
        };
      case "LOW":
      default:
        return {
          text: "text-emerald-400",
          bg: "bg-emerald-500/10",
          border: "border-emerald-500/30",
          badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
          gauge: "#10b981",
        };
    }
  };

  const colors = getRiskColor(level);

  function exportReportJson() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute(
      "download",
      `veritor-${report.package_name}-${report.version}-${report.scan_id}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  return (
    <div className="w-full space-y-6">
      {/* Top Banner Card */}
      <div className="p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                {report.ecosystem}
              </span>
              <h1 className="text-xl sm:text-2xl font-bold font-mono text-slate-100">
                {report.package_name}
              </h1>
              <span className="text-sm sm:text-base font-mono text-slate-400">
                v{report.version}
              </span>
              <span
                className={`text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full border ${colors.badge}`}
              >
                {level} RISK ({score}/100)
              </span>
            </div>

            <p className="text-xs text-slate-400 font-mono flex flex-wrap items-center gap-x-4 gap-y-1 pt-1">
              <span>Scan ID: {report.scan_id}</span>
              {report.duration_seconds !== null && report.duration_seconds !== undefined && (
                <span className="flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  {report.duration_seconds.toFixed(2)}s analysis
                </span>
              )}
              {report.source_match?.repository_url && (
                <span className="flex items-center gap-1 truncate max-w-xs sm:max-w-md">
                  <GitBranch className="w-3.5 h-3.5 text-slate-500" />
                  <a
                    href={report.source_match.repository_url}
                    target="_blank"
                    rel="noreferrer"
                    className="hover:text-emerald-400 underline decoration-slate-600"
                  >
                    {report.source_match.repository_url.replace("https://github.com/", "")}
                  </a>
                </span>
              )}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={exportReportJson}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-mono text-slate-300 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Export JSON</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 border-t border-slate-800 mt-6 pt-4 overflow-x-auto text-xs font-mono">
          <button
            onClick={() => setActiveReportTab("overview")}
            className={`px-3 py-1.5 rounded-md transition-colors ${
              activeReportTab === "overview"
                ? "bg-slate-800 text-emerald-400 border border-emerald-500/30 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Overview &amp; Risk
          </button>
          <button
            onClick={() => setActiveReportTab("files")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors ${
              activeReportTab === "files"
                ? "bg-slate-800 text-cyan-400 border border-cyan-500/30 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>Files &amp; Diffs</span>
            {comparison?.summary && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-900 text-slate-300 border border-slate-700">
                {comparison.summary.total_package_files}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveReportTab("findings")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors ${
              activeReportTab === "findings"
                ? "bg-slate-800 text-rose-400 border border-rose-500/30 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>Security Findings</span>
            {security?.findings && security.findings.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30">
                {security.findings.length}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveReportTab("provenance")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors ${
              activeReportTab === "provenance"
                ? "bg-slate-800 text-amber-400 border border-amber-500/30 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>Provenance</span>
            {provenance?.status && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-900 text-slate-300 border border-slate-700">
                {provenance.status}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveReportTab("ai")}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-colors ${
              activeReportTab === "ai"
                ? "bg-slate-800 text-violet-400 border border-violet-500/30 font-semibold"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-violet-400" />
            <span>AI Investigator</span>
          </button>
        </div>
      </div>

      {/* OVERVIEW TAB CONTENT */}
      {activeReportTab === "overview" && (
        <div className="space-y-6">
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Risk Score Dial Card */}
            <div className={`p-5 rounded-xl border ${colors.bg} ${colors.border} flex flex-col justify-between`}>
              <div>
                <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                  Risk Assessment
                </span>
                <div className="flex items-baseline gap-2 mt-2">
                  <span className={`text-4xl font-extrabold font-mono ${colors.text}`}>
                    {score}
                  </span>
                  <span className="text-xs font-mono text-slate-400">/ 100</span>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs font-mono text-slate-300">
                Level: <span className={`font-bold ${colors.text}`}>{level}</span>
                {risk?.confidence !== undefined && (
                  <span className="text-slate-400 block mt-0.5">
                    Confidence: {(risk.confidence * 100).toFixed(0)}%
                  </span>
                )}
              </div>
            </div>

            {/* Differential Summary */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
              <div>
                <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                  Source Diffs
                </span>
                <div className="flex items-baseline gap-3 mt-2 font-mono">
                  <span className="text-2xl font-bold text-emerald-400">
                    +{comparison?.summary?.added_files ?? 0}
                  </span>
                  <span className="text-2xl font-bold text-amber-400">
                    ~{comparison?.summary?.modified_files ?? 0}
                  </span>
                  <span className="text-2xl font-bold text-slate-400">
                    ={comparison?.summary?.identical_files ?? 0}
                  </span>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 text-xs font-mono text-slate-400">
                <span>{comparison?.summary?.total_package_files ?? 0} files in package</span>
              </div>
            </div>

            {/* Security Findings Summary */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
              <div>
                <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                  Static Findings
                </span>
                <div className="flex items-baseline gap-2 mt-2">
                  <span
                    className={`text-3xl font-extrabold font-mono ${
                      (security?.findings?.length ?? 0) > 0 ? "text-rose-400" : "text-emerald-400"
                    }`}
                  >
                    {security?.findings?.length ?? 0}
                  </span>
                  <span className="text-xs font-mono text-slate-400">detected</span>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 text-xs font-mono text-slate-400">
                <span>{security?.gaps?.length ?? 0} scanner limitations</span>
              </div>
            </div>

            {/* Provenance Card */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
              <div>
                <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                  Provenance
                </span>
                <div className="flex items-center gap-2 mt-2">
                  <span
                    className={`text-sm font-bold font-mono px-2.5 py-1 rounded border ${
                      provenance?.status === "VERIFIED"
                        ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                        : provenance?.status === "NOT_VERIFIED"
                        ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                        : "bg-slate-800 text-slate-300 border-slate-700"
                    }`}
                  >
                    {provenance?.status || "UNAVAILABLE"}
                  </span>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 text-xs font-mono text-slate-400 truncate">
                <span>{provenance?.sigstore_verified ? "Sigstore Verified" : "Unsigned Build"}</span>
              </div>
            </div>
          </div>

          {/* Hard Floors Notice (if triggered) */}
          {risk?.floors && risk.floors.some((f) => f.triggered) && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/40 space-y-2">
              <div className="flex items-center gap-2 text-rose-400 font-mono font-bold text-sm">
                <AlertOctagon className="w-4 h-4" />
                <span>Deterministic Hard Security Floor Triggered</span>
              </div>
              <div className="space-y-1.5 text-xs font-mono text-rose-200">
                {risk.floors
                  .filter((f) => f.triggered)
                  .map((floor, i) => (
                    <div key={i} className="flex items-start gap-2">
                      <span className="text-rose-400 font-bold">•</span>
                      <span>
                        <strong>{floor.name}</strong>: Enforced floor of {floor.min_score} points ({floor.reason})
                      </span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Contributing Factors & Recommendations 2-Column */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Contributing Factors */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="font-mono text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-emerald-400" />
                  Contributing Risk Factors
                </h3>
                <span className="text-xs font-mono text-slate-400">
                  {risk?.factors?.length ?? 0} factors
                </span>
              </div>

              {risk?.factors && risk.factors.length > 0 ? (
                <div className="space-y-2.5">
                  {risk.factors.map((f, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono flex items-start justify-between gap-3"
                    >
                      <div>
                        <span className="font-semibold text-slate-200">{f.factor}</span>
                        <p className="text-slate-400 mt-0.5">{f.details}</p>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded font-bold ${
                          f.points > 20
                            ? "bg-rose-500/20 text-rose-300"
                            : f.points > 0
                            ? "bg-amber-500/20 text-amber-300"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        +{f.points}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-400 font-mono py-4 text-center">
                  No elevated risk factors detected.
                </p>
              )}
            </div>

            {/* Recommendations & Limitations */}
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="font-mono text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  Actionable Recommendations
                </h3>
              </div>

              {risk?.recommendations && risk.recommendations.length > 0 ? (
                <ul className="space-y-2">
                  {risk.recommendations.map((rec, i) => (
                    <li
                      key={i}
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 flex items-start gap-2.5"
                    >
                      <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-400 font-mono py-4 text-center">
                  No specific recommendations necessary. Package appears standard.
                </p>
              )}

              {/* Limitations Disclosure */}
              {risk?.limitations && risk.limitations.length > 0 && (
                <div className="pt-2 border-t border-slate-800">
                  <h4 className="text-[11px] uppercase font-mono tracking-wider text-slate-400 mb-2">
                    Analysis Limitations
                  </h4>
                  <ul className="space-y-1 text-xs font-mono text-slate-400">
                    {risk.limitations.map((lim, i) => (
                      <li key={i} className="flex items-start gap-2">
                        <span className="text-slate-500">•</span>
                        <span>{lim}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

"use client";

import React from "react";
import {
  History,
  Trash2,
  Search,
  ArrowRight,
} from "lucide-react";
import { ScanHistoryItem } from "../lib/types";

interface ScanHistoryViewProps {
  history: ScanHistoryItem[];
  onSelectScan: (item: ScanHistoryItem) => void;
  onClearHistory: () => void;
  onScanNew: () => void;
}

export function ScanHistoryView({
  history,
  onSelectScan,
  onClearHistory,
  onScanNew,
}: ScanHistoryViewProps) {
  const getBadge = (level?: string | null) => {
    switch (level) {
      case "CRITICAL":
        return "bg-rose-500/20 text-rose-300 border-rose-500/40";
      case "HIGH":
        return "bg-orange-500/20 text-orange-300 border-orange-500/40";
      case "MEDIUM":
        return "bg-amber-500/20 text-amber-300 border-amber-500/40";
      case "LOW":
      default:
        return "bg-emerald-500/20 text-emerald-300 border-emerald-500/40";
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto my-6 p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2.5">
          <History className="w-5 h-5 text-emerald-400" />
          <h2 className="text-base font-bold text-slate-100">Scan History</h2>
          <span className="text-slate-500">({history.length} scans)</span>
        </div>

        <div className="flex items-center gap-2">
          {history.length > 0 && (
            <button
              onClick={onClearHistory}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/40 hover:text-rose-300 border border-slate-700 hover:border-rose-800 text-slate-300 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5 text-slate-400" />
              <span>Clear History</span>
            </button>
          )}
          <button
            onClick={onScanNew}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium transition-colors"
          >
            <Search className="w-3.5 h-3.5" />
            <span>New Scan</span>
          </button>
        </div>
      </div>

      {history.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase">
                <th className="py-2.5 px-3 font-semibold">Package</th>
                <th className="py-2.5 px-3 font-semibold">Version</th>
                <th className="py-2.5 px-3 font-semibold">Ecosystem</th>
                <th className="py-2.5 px-3 font-semibold">Risk Score</th>
                <th className="py-2.5 px-3 font-semibold">Date</th>
                <th className="py-2.5 px-3 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {history.map((item) => (
                <tr
                  key={item.scan_id}
                  onClick={() => onSelectScan(item)}
                  className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                >
                  <td className="py-3 px-3 font-bold text-slate-200 group-hover:text-emerald-300">
                    {item.package_name}
                  </td>
                  <td className="py-3 px-3 text-slate-400">
                    {item.version}
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                      {item.ecosystem}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    {item.risk_score !== null && item.risk_score !== undefined ? (
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getBadge(
                          item.risk_level
                        )}`}
                      >
                        {item.risk_score}/100 ({item.risk_level})
                      </span>
                    ) : (
                      <span className="text-slate-500">—</span>
                    )}
                  </td>
                  <td className="py-3 px-3 text-slate-500 text-[11px]">
                    {new Date(item.timestamp).toLocaleDateString()} {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <span className="inline-flex items-center gap-1 text-slate-400 group-hover:text-emerald-400 text-[11px]">
                      <span>View</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="p-12 text-center text-slate-500 space-y-3">
          <History className="w-8 h-8 mx-auto text-slate-600" />
          <h3 className="text-slate-300 font-bold text-sm">No Scans Recorded Yet</h3>
          <p className="text-slate-400 max-w-sm mx-auto">
            Run a package analysis from the scanner tab to see historical risk scores and provenance status here.
          </p>
          <button
            onClick={onScanNew}
            className="mt-2 inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors"
          >
            Start First Scan
          </button>
        </div>
      )}
    </div>
  );
}

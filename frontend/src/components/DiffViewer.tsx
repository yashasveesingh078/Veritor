"use client";

import React, { useState } from "react";
import {
  Copy,
  Check,
  Columns,
  AlignJustify,
  FileCode,
  FileCheck,
} from "lucide-react";
import { FileDiffItem } from "../lib/types";

interface DiffViewerProps {
  diff: FileDiffItem | null;
  isLoading: boolean;
  filePath: string;
}

export function DiffViewer({ diff, isLoading, filePath }: DiffViewerProps) {
  const [viewMode, setViewMode] = useState<"unified" | "split">("unified");
  const [copied, setCopied] = useState(false);

  function copyDiff() {
    if (!diff?.unified) return;
    navigator.clipboard.writeText(diff.unified);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (isLoading) {
    return (
      <div className="w-full h-full min-h-[400px] flex items-center justify-center bg-slate-900/90 rounded-xl border border-slate-800 p-8">
        <div className="flex flex-col items-center gap-3 text-slate-400 font-mono text-xs">
          <div className="w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
          <span>Loading diff for {filePath}...</span>
        </div>
      </div>
    );
  }

  if (!diff) {
    return (
      <div className="w-full h-full min-h-[400px] flex items-center justify-center bg-slate-900/90 rounded-xl border border-slate-800 p-8 text-center text-slate-500 font-mono text-xs">
        <div className="space-y-2">
          <FileCode className="w-8 h-8 mx-auto text-slate-600" />
          <p>Select a file from the explorer to view differences.</p>
        </div>
      </div>
    );
  }

  const lines = diff.unified ? diff.unified.split("\n") : [];
  const isIdentical = diff.diff_status === "CLEAN" || (!diff.unified && diff.status === "IDENTICAL");
  const isBinary = diff.diff_status === "BINARY";

  return (
    <div className="w-full h-full flex flex-col bg-slate-950 rounded-xl border border-slate-800 overflow-hidden font-mono text-xs shadow-xl">
      {/* Diff Header Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-2 truncate">
          <FileCode className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="font-bold text-slate-200 truncate">{filePath}</span>
          <span
            className={`text-[10px] px-2 py-0.5 rounded border ${
              diff.status === "ADDED"
                ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                : diff.status === "MODIFIED"
                ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                : "bg-slate-800 text-slate-400 border-slate-700"
            }`}
          >
            {diff.status}
          </span>
          {diff.classification && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              {diff.classification}
            </span>
          )}
        </div>

        <div className="flex items-center gap-3">
          {/* Additions / Removals Counter */}
          <div className="flex items-center gap-2 text-xs">
            {diff.added_lines !== undefined && diff.added_lines !== null && (
              <span className="text-emerald-400">+{diff.added_lines}</span>
            )}
            {diff.removed_lines !== undefined && diff.removed_lines !== null && (
              <span className="text-rose-400">-{diff.removed_lines}</span>
            )}
          </div>

          {/* View Mode Toggle */}
          <div className="flex items-center bg-slate-950 p-0.5 rounded-lg border border-slate-800">
            <button
              onClick={() => setViewMode("unified")}
              className={`p-1.5 rounded transition-colors ${
                viewMode === "unified"
                  ? "bg-slate-800 text-slate-100"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Unified View"
            >
              <AlignJustify className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setViewMode("split")}
              className={`p-1.5 rounded transition-colors ${
                viewMode === "split"
                  ? "bg-slate-800 text-slate-100"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Side-by-side View"
            >
              <Columns className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Copy Button */}
          {diff.unified && (
            <button
              onClick={copyDiff}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors"
              title="Copy diff to clipboard"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-400" />
                  <span>Copy</span>
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Diff Content Body */}
      <div className="flex-1 overflow-x-auto overflow-y-auto max-h-[600px] p-3 text-xs font-mono leading-relaxed bg-slate-950">
        {isIdentical ? (
          <div className="py-16 text-center text-slate-500 space-y-2">
            <FileCheck className="w-8 h-8 mx-auto text-emerald-500/60" />
            <p className="text-slate-300">File is identical between source and published package.</p>
            <p className="text-[11px] text-slate-500">Zero modifications or extra injected payload.</p>
          </div>
        ) : isBinary ? (
          <div className="py-16 text-center text-slate-500 space-y-2">
            <FileCode className="w-8 h-8 mx-auto text-cyan-500/60" />
            <p className="text-slate-300">Binary file (diff cannot be displayed in text view).</p>
          </div>
        ) : lines.length > 0 ? (
          <table className="w-full border-collapse">
            <tbody>
              {lines.map((line, idx) => {
                const isAddition = line.startsWith("+") && !line.startsWith("+++");
                const isDeletion = line.startsWith("-") && !line.startsWith("---");
                const isHeader = line.startsWith("@@") || line.startsWith("---") || line.startsWith("+++");

                return (
                  <tr
                    key={idx}
                    className={`${
                      isAddition
                        ? "bg-emerald-950/40 text-emerald-300"
                        : isDeletion
                        ? "bg-rose-950/40 text-rose-300"
                        : isHeader
                        ? "bg-slate-900/80 text-cyan-400 font-semibold"
                        : "text-slate-300 hover:bg-slate-900/40"
                    }`}
                  >
                    <td className="w-10 pr-3 text-right select-none text-slate-600 border-r border-slate-800">
                      {idx + 1}
                    </td>
                    <td className="pl-3 whitespace-pre font-mono">
                      {line}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div className="py-16 text-center text-slate-500">
            <p>No textual diff content returned for this file.</p>
          </div>
        )}
      </div>
    </div>
  );
}

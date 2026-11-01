"use client";

import React, { useState, useMemo } from "react";
import {
  FileCode,
  FilePlus,
  FileDiff,
  FileCheck,
  Search,
  Filter,
} from "lucide-react";
import { ArtifactClassification, PackageFileItem } from "../lib/types";

interface FileExplorerProps {
  files: PackageFileItem[];
  selectedFilePath: string | null;
  onSelectFile: (path: string) => void;
}

export function FileExplorer({
  files,
  selectedFilePath,
  onSelectFile,
}: FileExplorerProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [classificationFilter, setClassificationFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const filteredFiles = useMemo(() => {
    return files.filter((f) => {
      // Search query
      if (searchQuery.trim() && !f.path.toLowerCase().includes(searchQuery.toLowerCase().trim())) {
        return false;
      }

      // Classification filter
      if (classificationFilter !== "ALL") {
        if (f.classification !== classificationFilter) {
          return false;
        }
      }

      // Status filter
      if (statusFilter !== "ALL") {
        if (f.status !== statusFilter) {
          return false;
        }
      }

      return true;
    });
  }, [files, searchQuery, classificationFilter, statusFilter]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "ADDED":
        return <FilePlus className="w-4 h-4 text-emerald-400 shrink-0" />;
      case "MODIFIED":
        return <FileDiff className="w-4 h-4 text-amber-400 shrink-0" />;
      case "REMOVED":
        return <FileCode className="w-4 h-4 text-rose-400 shrink-0" />;
      case "IDENTICAL":
      default:
        return <FileCheck className="w-4 h-4 text-slate-500 shrink-0" />;
    }
  };

  const getClassificationBadge = (cls?: ArtifactClassification) => {
    if (!cls) return null;
    switch (cls) {
      case "SUSPICIOUS":
        return (
          <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
            SUSPICIOUS
          </span>
        );
      case "UNCERTAIN":
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
            UNCERTAIN
          </span>
        );
      case "LIKELY_GENERATED":
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
            GENERATED
          </span>
        );
      case "SOURCE_AUTHENTIC":
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
            AUTHENTIC
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="w-full h-full flex flex-col bg-slate-900/90 rounded-xl border border-slate-800 overflow-hidden">
      {/* Header & Controls */}
      <div className="p-3.5 border-b border-slate-800 space-y-2.5">
        <div className="relative">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search files by path or extension..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
          <span className="text-slate-500 mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3" /> Filter:
          </span>

          {/* Classification Filter Buttons */}
          {["ALL", "SUSPICIOUS", "LIKELY_GENERATED", "UNCERTAIN"].map((c) => (
            <button
              key={c}
              onClick={() => setClassificationFilter(c)}
              className={`px-2 py-0.5 rounded transition-colors ${
                classificationFilter === c
                  ? "bg-slate-700 text-emerald-300 font-semibold border border-slate-600"
                  : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
              }`}
            >
              {c === "ALL" ? "All Artifacts" : c.replace("_", " ")}
            </button>
          ))}

          {/* Status Filter Buttons */}
          {["ADDED", "MODIFIED"].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(statusFilter === s ? "ALL" : s)}
              className={`px-2 py-0.5 rounded transition-colors ${
                statusFilter === s
                  ? "bg-cyan-950/80 text-cyan-300 font-semibold border border-cyan-800"
                  : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Files List */}
      <div className="flex-1 overflow-y-auto max-h-[600px] divide-y divide-slate-800/60 font-mono text-xs">
        {filteredFiles.length > 0 ? (
          filteredFiles.map((file) => {
            const isSelected = selectedFilePath === file.path;
            return (
              <div
                key={file.path}
                onClick={() => onSelectFile(file.path)}
                className={`flex items-center justify-between p-2.5 cursor-pointer transition-colors ${
                  isSelected
                    ? "bg-slate-800 text-emerald-300 border-l-2 border-emerald-400 pl-2"
                    : "hover:bg-slate-800/50 text-slate-300"
                }`}
              >
                <div className="flex items-center gap-2 truncate pr-2">
                  {getStatusIcon(file.status)}
                  <span className="truncate" title={file.path}>
                    {file.path}
                  </span>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {getClassificationBadge(file.classification)}
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded ${
                      file.status === "ADDED"
                        ? "text-emerald-400"
                        : file.status === "MODIFIED"
                        ? "text-amber-400"
                        : "text-slate-500"
                    }`}
                  >
                    {file.status}
                  </span>
                </div>
              </div>
            );
          })
        ) : (
          <div className="p-8 text-center text-slate-500">
            <p>No files match current filters.</p>
          </div>
        )}
      </div>

      {/* Footer Summary */}
      <div className="p-2.5 border-t border-slate-800 bg-slate-950/40 text-[11px] font-mono text-slate-400 flex items-center justify-between">
        <span>Showing {filteredFiles.length} of {files.length} files</span>
        {selectedFilePath && (
          <span className="text-emerald-400 truncate max-w-[200px]" title={selectedFilePath}>
            {selectedFilePath}
          </span>
        )}
      </div>
    </div>
  );
}

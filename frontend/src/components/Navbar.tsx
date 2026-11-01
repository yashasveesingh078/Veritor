"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  History,
  Bookmark,
  Settings as SettingsIcon,
  Cpu,
  Server,
  Sparkles,
} from "lucide-react";
import { checkBackendHealth, checkOllamaConnection } from "../lib/api";

interface NavbarProps {
  activeTab: "scanner" | "report" | "history" | "watchlist" | "settings";
  setActiveTab: (tab: "scanner" | "report" | "history" | "watchlist" | "settings") => void;
  hasActiveReport: boolean;
  historyCount: number;
  watchlistCount: number;
}

export function Navbar({
  activeTab,
  setActiveTab,
  hasActiveReport,
  historyCount,
  watchlistCount,
}: NavbarProps) {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [ollamaOnline, setOllamaOnline] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;

    async function checkStatus() {
      try {
        const backend = await checkBackendHealth();
        if (mounted) {
          setBackendOnline(backend.status === "ok");
        }
      } catch {
        if (mounted) setBackendOnline(false);
      }

      try {
        const ollama = await checkOllamaConnection();
        if (mounted) {
          setOllamaOnline(ollama.connected);
        }
      } catch {
        if (mounted) setOllamaOnline(false);
      }
    }

    checkStatus();
    const interval = setInterval(checkStatus, 15000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header className="sticky top-0 z-50 backdrop-blur-md bg-slate-950/80 border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand */}
          <div
            onClick={() => setActiveTab("scanner")}
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="relative p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 group-hover:border-emerald-500/60 transition-colors">
              <ShieldAlert className="w-5 h-5 text-emerald-400" />
              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-wider text-slate-100 font-mono text-lg">
                  VERITOR
                </span>
                <span className="text-[10px] uppercase font-semibold tracking-wider px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  SUPPLY CHAIN
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">
                Artifact &amp; Provenance Intelligence
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            <button
              onClick={() => setActiveTab("scanner")}
              className={`px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-all ${
                activeTab === "scanner"
                  ? "bg-slate-800 text-emerald-400 border border-emerald-500/30 shadow-sm shadow-emerald-950"
                  : "text-slate-300 hover:text-slate-100 hover:bg-slate-900"
              }`}
            >
              Scanner
            </button>

            {hasActiveReport && (
              <button
                onClick={() => setActiveTab("report")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-all ${
                  activeTab === "report"
                    ? "bg-slate-800 text-cyan-400 border border-cyan-500/30 shadow-sm"
                    : "text-slate-300 hover:text-slate-100 hover:bg-slate-900"
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                Report
              </button>
            )}

            <button
              onClick={() => setActiveTab("history")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-all ${
                activeTab === "history"
                  ? "bg-slate-800 text-slate-100 border border-slate-700"
                  : "text-slate-300 hover:text-slate-100 hover:bg-slate-900"
              }`}
            >
              <History className="w-3.5 h-3.5 text-slate-400" />
              <span>History</span>
              {historyCount > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                  {historyCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("watchlist")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs sm:text-sm font-medium transition-all ${
                activeTab === "watchlist"
                  ? "bg-slate-800 text-slate-100 border border-slate-700"
                  : "text-slate-300 hover:text-slate-100 hover:bg-slate-900"
              }`}
            >
              <Bookmark className="w-3.5 h-3.5 text-slate-400" />
              <span className="hidden sm:inline">Watchlist</span>
              {watchlistCount > 0 && (
                <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-slate-800 text-amber-300 border border-amber-500/30">
                  {watchlistCount}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveTab("settings")}
              className={`p-2 rounded-md text-xs sm:text-sm font-medium transition-all ${
                activeTab === "settings"
                  ? "bg-slate-800 text-slate-100 border border-slate-700"
                  : "text-slate-400 hover:text-slate-100 hover:bg-slate-900"
              }`}
              title="Settings & System Status"
            >
              <SettingsIcon className="w-4 h-4" />
            </button>
          </nav>

          {/* System Status Indicators */}
          <div className="hidden md:flex items-center gap-3 border-l border-slate-800 pl-4 text-xs font-mono">
            {/* Backend status */}
            <div
              className="flex items-center gap-1.5"
              title={backendOnline ? "FastAPI Backend is Online" : "FastAPI Backend is Offline"}
            >
              <Server className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">API:</span>
              <span
                className={`w-2 h-2 rounded-full ${
                  backendOnline === null
                    ? "bg-slate-500 animate-pulse"
                    : backendOnline
                    ? "bg-emerald-500 shadow-sm shadow-emerald-500"
                    : "bg-rose-500"
                }`}
              />
            </div>

            {/* Ollama status */}
            <div
              className="flex items-center gap-1.5"
              title={
                ollamaOnline
                  ? "Ollama AI Engine Connected (qwen2.5-coder:7b ready)"
                  : "Ollama Offline (Deterministic Fallback Active)"
              }
            >
              <Cpu className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-slate-400">AI:</span>
              <span
                className={`w-2 h-2 rounded-full ${
                  ollamaOnline === null
                    ? "bg-slate-500 animate-pulse"
                    : ollamaOnline
                    ? "bg-cyan-400 shadow-sm shadow-cyan-400"
                    : "bg-amber-500"
                }`}
              />
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

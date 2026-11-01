"use client";

import React, { useState, useEffect } from "react";
import {
  Settings,
  Server,
  Cpu,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Save,
  Shield,
} from "lucide-react";
import {
  checkBackendHealth,
  checkOllamaConnection,
  getApiBaseUrl,
  setApiBaseUrl,
} from "../lib/api";

export function SettingsView() {
  const [apiUrl, setApiUrl] = useState(() => getApiBaseUrl());
  const [ollamaUrl, setOllamaUrl] = useState("http://127.0.0.1:11434");
  const [backendStatus, setBackendStatus] = useState<string>("checking");
  const [ollamaStatus, setOllamaStatus] = useState<boolean | null>(null);
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [isSaved, setIsSaved] = useState(false);
  const [isTesting, setIsTesting] = useState(false);

  useEffect(() => {
    let mounted = true;
    const fetchStatus = async () => {
      try {
        const backend = await checkBackendHealth();
        if (mounted) setBackendStatus(backend.status);
      } catch {
        if (mounted) setBackendStatus("disconnected");
      }

      try {
        const ollama = await checkOllamaConnection(ollamaUrl);
        if (mounted) {
          setOllamaStatus(ollama.connected);
          setOllamaModels(ollama.models);
        }
      } catch {
        if (mounted) {
          setOllamaStatus(false);
          setOllamaModels([]);
        }
      }
    };

    fetchStatus();
    return () => {
      mounted = false;
    };
  }, [ollamaUrl]);

  async function testConnections() {
    setIsTesting(true);
    try {
      const backend = await checkBackendHealth();
      setBackendStatus(backend.status);
    } catch {
      setBackendStatus("disconnected");
    }

    try {
      const ollama = await checkOllamaConnection(ollamaUrl);
      setOllamaStatus(ollama.connected);
      setOllamaModels(ollama.models);
    } catch {
      setOllamaStatus(false);
      setOllamaModels([]);
    }
    setIsTesting(false);
  }

  function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setApiBaseUrl(apiUrl);
    setIsSaved(true);
    testConnections();
    setTimeout(() => setIsSaved(false), 2500);
  }

  return (
    <div className="w-full max-w-3xl mx-auto my-6 p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6 font-mono text-xs">
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2.5">
          <Settings className="w-5 h-5 text-slate-300" />
          <h2 className="text-base font-bold text-slate-100">Settings &amp; Infrastructure</h2>
        </div>
        <button
          onClick={testConnections}
          disabled={isTesting}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isTesting ? "animate-spin" : ""}`} />
          <span>Test Health</span>
        </button>
      </div>

      {/* Backend API Configuration */}
      <form onSubmit={handleSave} className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-200 font-bold text-sm">
            <Server className="w-4 h-4 text-emerald-400" />
            <span>FastAPI Backend Connection</span>
          </div>
          <div className="flex items-center gap-1.5">
            {backendStatus === "ok" ? (
              <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400">
                <CheckCircle2 className="w-3.5 h-3.5" /> Online
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[11px] text-rose-400">
                <XCircle className="w-3.5 h-3.5" /> Offline
              </span>
            )}
          </div>
        </div>

        <div>
          <label className="block text-slate-400 mb-1 text-[11px]">API BASE URL</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              placeholder="http://localhost:8000"
              className="flex-1 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
            />
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium transition-colors"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Save</span>
            </button>
          </div>
        </div>

        {isSaved && (
          <p className="text-emerald-400 text-[11px] flex items-center gap-1">
            <CheckCircle2 className="w-3.5 h-3.5" /> Saved successfully.
          </p>
        )}
      </form>

      {/* Ollama Local AI Configuration */}
      <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-slate-200 font-bold text-sm">
            <Cpu className="w-4 h-4 text-violet-400" />
            <span>Ollama AI Inference Engine</span>
          </div>
          <div className="flex items-center gap-1.5">
            {ollamaStatus ? (
              <span className="inline-flex items-center gap-1 text-[11px] text-cyan-400">
                <CheckCircle2 className="w-3.5 h-3.5" /> Connected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 text-[11px] text-amber-400">
                <XCircle className="w-3.5 h-3.5" /> Offline (Fallback Active)
              </span>
            )}
          </div>
        </div>

        <p className="text-slate-400 text-xs">
          Veritor integrates with a local Ollama server running <code className="text-violet-300">qwen2.5-coder:7b</code> for deep diff explanation without external data egress.
        </p>

        <div>
          <label className="block text-slate-400 mb-1 text-[11px]">OLLAMA SERVER URL</label>
          <input
            type="text"
            value={ollamaUrl}
            onChange={(e) => setOllamaUrl(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-violet-500"
          />
        </div>

        {ollamaModels.length > 0 && (
          <div>
            <span className="text-slate-500 text-[11px] uppercase block mb-1.5">
              Available Local Models ({ollamaModels.length})
            </span>
            <div className="flex flex-wrap gap-1.5">
              {ollamaModels.map((m) => (
                <span
                  key={m}
                  className={`px-2 py-0.5 rounded text-[11px] border ${
                    m.includes("qwen") || m.includes("phi4")
                      ? "bg-violet-500/20 text-violet-300 border-violet-500/40 font-semibold"
                      : "bg-slate-900 text-slate-400 border-slate-800"
                  }`}
                >
                  {m}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Security Engine Limits & Boundaries */}
      <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
        <div className="flex items-center gap-2 text-slate-200 font-bold text-sm">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span>Security Engine Boundaries</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-400 text-xs">
          <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
            <span className="text-slate-500 text-[10px] uppercase block">Max Tarball Archive</span>
            <span className="text-slate-200 font-semibold">50 MB</span>
          </div>
          <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
            <span className="text-slate-500 text-[10px] uppercase block">Max File Diff Size</span>
            <span className="text-slate-200 font-semibold">2 MB / 10,000 lines</span>
          </div>
          <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
            <span className="text-slate-500 text-[10px] uppercase block">Max Extracted Entries</span>
            <span className="text-slate-200 font-semibold">10,000 files</span>
          </div>
          <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
            <span className="text-slate-500 text-[10px] uppercase block">Max Compression Ratio</span>
            <span className="text-slate-200 font-semibold">50:1 (Zip Bomb Guard)</span>
          </div>
        </div>
      </div>
    </div>
  );
}

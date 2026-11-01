"use client";

import React, { useState } from "react";
import {
  Bookmark,
  BookmarkPlus,
  Trash2,
  Search,
  Plus,
} from "lucide-react";
import { addToWatchlist, removeFromWatchlist } from "../lib/storage";
import { Ecosystem, WatchlistItem } from "../lib/types";

interface WatchlistViewProps {
  watchlist: WatchlistItem[];
  onTriggerScan: (ecosystem: Ecosystem, packageName: string) => void;
  onRefresh: () => void;
}

export function WatchlistView({
  watchlist,
  onTriggerScan,
  onRefresh,
}: WatchlistViewProps) {
  const [newEcosystem, setNewEcosystem] = useState<Ecosystem>("npm");
  const [newPackage, setNewPackage] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);

  function handleAdd(e: React.FormEvent) {
    e.preventDefault();
    const pkg = newPackage.trim();
    if (!pkg) {
      setError("Package name cannot be empty.");
      return;
    }
    setError(null);
    addToWatchlist({
      ecosystem: newEcosystem,
      package_name: pkg,
      notes: notes.trim() || undefined,
    });
    setNewPackage("");
    setNotes("");
    onRefresh();
  }

  function handleRemove(id: string) {
    removeFromWatchlist(id);
    onRefresh();
  }

  return (
    <div className="w-full max-w-4xl mx-auto my-6 p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-xl space-y-6 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2.5">
          <Bookmark className="w-5 h-5 text-amber-400" />
          <h2 className="text-base font-bold text-slate-100">Package Watchlist</h2>
          <span className="text-slate-500">({watchlist.length} monitored)</span>
        </div>
      </div>

      {/* Add New Package Form */}
      <form onSubmit={handleAdd} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
        <h3 className="text-xs uppercase text-slate-400 font-semibold tracking-wider flex items-center gap-1.5">
          <BookmarkPlus className="w-4 h-4 text-emerald-400" />
          <span>Monitor New Package</span>
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
          <div>
            <select
              value={newEcosystem}
              onChange={(e) => setNewEcosystem(e.target.value as Ecosystem)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-amber-500"
            >
              <option value="npm">npm</option>
              <option value="pypi">PyPI</option>
            </select>
          </div>

          <div className="sm:col-span-2">
            <input
              type="text"
              value={newPackage}
              onChange={(e) => setNewPackage(e.target.value)}
              placeholder="Package name (e.g. @types/node, requests)"
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-200 text-xs placeholder-slate-500 focus:outline-none focus:border-amber-500"
              required
            />
          </div>

          <div>
            <button
              type="submit"
              className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-medium transition-colors"
            >
              <Plus className="w-4 h-4" />
              <span>Add Watch</span>
            </button>
          </div>
        </div>

        {error && <p className="text-rose-400 text-[11px]">{error}</p>}
      </form>

      {/* Watchlist Table */}
      {watchlist.length > 0 ? (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase">
                <th className="py-2.5 px-3 font-semibold">Package</th>
                <th className="py-2.5 px-3 font-semibold">Ecosystem</th>
                <th className="py-2.5 px-3 font-semibold">Last Checked</th>
                <th className="py-2.5 px-3 font-semibold">Risk Level</th>
                <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {watchlist.map((item) => (
                <tr key={item.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-3 font-bold text-slate-200">
                    {item.package_name}
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                      {item.ecosystem}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-slate-400 text-[11px]">
                    {item.last_scanned_version ? (
                      <span>v{item.last_scanned_version}</span>
                    ) : (
                      <span className="text-slate-600">Never</span>
                    )}
                  </td>
                  <td className="py-3 px-3">
                    {item.last_risk_score !== undefined && item.last_risk_score !== null ? (
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                        {item.last_risk_score}/100 ({item.last_risk_level})
                      </span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button
                        onClick={() => onTriggerScan(item.ecosystem, item.package_name)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-emerald-400 text-[11px] transition-colors"
                        title="Scan package now"
                      >
                        <Search className="w-3.5 h-3.5" />
                        <span>Scan</span>
                      </button>
                      <button
                        onClick={() => handleRemove(item.id)}
                        className="p-1 rounded text-slate-500 hover:text-rose-400 transition-colors"
                        title="Remove from watchlist"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="p-12 text-center text-slate-500 space-y-2">
          <Bookmark className="w-8 h-8 mx-auto text-slate-600" />
          <h3 className="text-slate-300 font-bold text-sm">Watchlist is Empty</h3>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            Add critical upstream dependencies to track release updates and quickly trigger integrity scans.
          </p>
        </div>
      )}
    </div>
  );
}

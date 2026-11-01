"use client";

import React, { useState } from "react";
import {
  Search,
  AlertCircle,
  BookmarkPlus,
  Loader2,
  Terminal,
} from "lucide-react";
import { Ecosystem, ScanRequest } from "../lib/types";

interface ScannerFormProps {
  onSubmit: (request: ScanRequest) => Promise<void>;
  isLoading: boolean;
  initialEcosystem?: Ecosystem;
  initialPackage?: string;
  initialVersion?: string;
  onAddToWatchlist?: (ecosystem: Ecosystem, packageName: string) => void;
}

const NPM_REGEX = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[A-Za-z0-9][A-Za-z0-9._~-]*$/;
const PYPI_REGEX = /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/;
const SEMVER_REGEX = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$/;

export function ScannerForm({
  onSubmit,
  isLoading,
  initialEcosystem = "npm",
  initialPackage = "",
  initialVersion = "",
  onAddToWatchlist,
}: ScannerFormProps) {
  const [ecosystem, setEcosystem] = useState<Ecosystem>(initialEcosystem);
  const [packageName, setPackageName] = useState<string>(initialPackage);
  const [version, setVersion] = useState<string>(initialVersion);
  const [validationError, setValidationError] = useState<string | null>(null);

  function validate(): string | null {
    const trimmedPkg = packageName.trim();
    const trimmedVer = version.trim();

    if (!trimmedPkg) {
      return "Package name is required.";
    }
    if (!trimmedVer) {
      return "Exact version is required. Veritor requires exact published versions (tags such as 'latest' are rejected).";
    }
    if (trimmedVer.toLowerCase() === "latest") {
      return "Tags like 'latest' are not supported. Specify an exact version (e.g. 1.3.0).";
    }

    if (ecosystem === "npm") {
      if (!NPM_REGEX.test(trimmedPkg)) {
        return "Invalid npm package name format (e.g. 'express' or '@types/node').";
      }
      if (!SEMVER_REGEX.test(trimmedVer)) {
        return "Invalid npm version. Must be an exact semantic version (e.g. '1.3.0' or '2.0.0-rc.1').";
      }
    } else {
      if (!PYPI_REGEX.test(trimmedPkg)) {
        return "Invalid PyPI package name format (e.g. 'requests' or 'urllib3').";
      }
      if (!/^\d+(\.\d+)*((\.dev|rc|a|b|post)\d+)?$/.test(trimmedVer)) {
        return "Invalid PyPI version format (PEP 440, e.g. '2.31.0').";
      }
    }

    return null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const err = validate();
    if (err) {
      setValidationError(err);
      return;
    }
    setValidationError(null);

    await onSubmit({
      ecosystem,
      package_name: packageName.trim(),
      version: version.trim(),
    });
  }

  return (
    <div className="w-full max-w-3xl mx-auto my-6 p-5 sm:p-6 rounded-xl bg-slate-900/90 border border-slate-800 shadow-2xl relative">
      <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2 text-slate-200">
          <Terminal className="w-5 h-5 text-emerald-400" />
          <h2 className="font-semibold text-sm sm:text-base tracking-wide">
            Package Integrity Scanner
          </h2>
        </div>
        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800">
          <button
            type="button"
            onClick={() => setEcosystem("npm")}
            className={`px-3 py-1 rounded text-xs font-mono font-medium transition-all ${
              ecosystem === "npm"
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            npm
          </button>
          <button
            type="button"
            onClick={() => setEcosystem("pypi")}
            className={`px-3 py-1 rounded text-xs font-mono font-medium transition-all ${
              ecosystem === "pypi"
                ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            PyPI
          </button>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="sm:col-span-2 space-y-1">
            <label className="block text-xs font-mono text-slate-400">
              PACKAGE NAME
            </label>
            <div className="relative">
              <input
                type="text"
                value={packageName}
                onChange={(e) => {
                  setPackageName(e.target.value);
                  if (validationError) setValidationError(null);
                }}
                placeholder={ecosystem === "npm" ? "e.g. left-pad, @types/node" : "e.g. requests, urllib3"}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
                disabled={isLoading}
                required
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="block text-xs font-mono text-slate-400">
              EXACT VERSION
            </label>
            <input
              type="text"
              value={version}
              onChange={(e) => {
                setVersion(e.target.value);
                if (validationError) setValidationError(null);
              }}
              placeholder={ecosystem === "npm" ? "1.3.0" : "2.31.0"}
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
              disabled={isLoading}
              required
            />
          </div>
        </div>

        {validationError && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono animate-fadeIn">
            <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
            <span>{validationError}</span>
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2">
            {onAddToWatchlist && packageName.trim() && (
              <button
                type="button"
                onClick={() => onAddToWatchlist(ecosystem, packageName.trim())}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-300 transition-colors font-medium"
              >
                <BookmarkPlus className="w-3.5 h-3.5 text-amber-400" />
                <span>Add to Watchlist</span>
              </button>
            )}
            <span className="text-[11px] text-slate-500 hidden sm:inline">
              Exact source verification via git &amp; package registries.
            </span>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white font-medium text-sm transition-all shadow-lg shadow-emerald-950 disabled:opacity-50 disabled:cursor-not-allowed group"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-emerald-200" />
                <span>Analyzing Package...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4 text-emerald-200 group-hover:scale-110 transition-transform" />
                <span>Scan Package</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}

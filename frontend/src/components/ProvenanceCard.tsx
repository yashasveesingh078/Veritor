"use client";

import React from "react";
import {
  Lock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  GitCommit,
  GitBranch,
  ShieldCheck,
  Key,
} from "lucide-react";
import { ProvenanceResult, ProvenanceStatus } from "../lib/types";

interface ProvenanceCardProps {
  provenance: ProvenanceResult | null | undefined;
  packageName: string;
  version: string;
}

export function ProvenanceCard({
  provenance,
  packageName,
  version,
}: ProvenanceCardProps) {
  const status: ProvenanceStatus = provenance?.status ?? "UNAVAILABLE";

  const getStatusBadge = (st: ProvenanceStatus) => {
    switch (st) {
      case "VERIFIED":
        return {
          icon: CheckCircle2,
          color: "text-emerald-400",
          bg: "bg-emerald-500/10",
          border: "border-emerald-500/30",
          badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
          label: "VERIFIED CRYPTOGRAPHICALLY",
          desc: "Package build identity cryptographically verified via Sigstore transparency logs.",
        };
      case "NOT_VERIFIED":
        return {
          icon: AlertTriangle,
          color: "text-amber-400",
          bg: "bg-amber-500/10",
          border: "border-amber-500/30",
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          label: "NOT VERIFIED",
          desc: "Attestation exists but could not be fully verified against expected identity.",
        };
      case "INVALID":
        return {
          icon: XCircle,
          color: "text-rose-400",
          bg: "bg-rose-500/10",
          border: "border-rose-500/30",
          badge: "bg-rose-500/20 text-rose-300 border-rose-500/40",
          label: "INVALID ATTESTATION",
          desc: "Signature mismatch or tampered payload attestation detected.",
        };
      case "UNCERTAIN":
        return {
          icon: HelpCircle,
          color: "text-amber-400",
          bg: "bg-amber-500/10",
          border: "border-amber-500/30",
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          label: "UNCERTAIN",
          desc: "Partial attestation data available, verification inconclusive.",
        };
      case "UNAVAILABLE":
      default:
        return {
          icon: Lock,
          color: "text-slate-400",
          bg: "bg-slate-900",
          border: "border-slate-800",
          badge: "bg-slate-800 text-slate-400 border-slate-700",
          label: "PROVENANCE UNAVAILABLE",
          desc: "Package was published without Sigstore cryptographic provenance attestations.",
        };
    }
  };

  const statusConfig = getStatusBadge(status);
  const StatusIcon = statusConfig.icon;

  return (
    <div className="w-full space-y-6 font-mono text-xs">
      {/* Main Status Header Card */}
      <div className={`p-6 rounded-xl border ${statusConfig.bg} ${statusConfig.border} shadow-lg space-y-4`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-lg bg-slate-950 border ${statusConfig.border}`}>
              <StatusIcon className={`w-6 h-6 ${statusConfig.color}`} />
            </div>
            <div>
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${statusConfig.badge}`}>
                {statusConfig.label}
              </span>
              <h2 className="text-sm sm:text-base font-bold text-slate-200 mt-1">
                Build &amp; Origin Attestation
              </h2>
            </div>
          </div>

          <div className="text-right text-slate-400">
            <span>{packageName}@{version}</span>
          </div>
        </div>

        <p className="text-slate-300 text-xs leading-relaxed">
          {statusConfig.desc}
        </p>

        {/* Verification Checkpoints Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 pt-2">
          {/* Sigstore */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase text-slate-500 flex items-center gap-1">
              <Key className="w-3 h-3" /> Sigstore Attestation
            </span>
            <div className="flex items-center gap-1.5 font-bold">
              {provenance?.sigstore_verified ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-300">Verified</span>
                </>
              ) : (
                <>
                  <XCircle className="w-3.5 h-3.5 text-slate-500" />
                  <span className="text-slate-400">Not Present</span>
                </>
              )}
            </div>
          </div>

          {/* GitHub Actions Runner */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase text-slate-500 flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" /> CI/CD Identity
            </span>
            <div className="truncate font-bold text-slate-200" title={provenance?.build_runner || "None"}>
              {provenance?.build_runner ? "GitHub Actions" : "Unsigned / Direct"}
            </div>
          </div>

          {/* Source Repo Match */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase text-slate-500 flex items-center gap-1">
              <GitBranch className="w-3 h-3" /> Repository Match
            </span>
            <div className="flex items-center gap-1.5 font-bold">
              {provenance?.repository_matched ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-300">Matched</span>
                </>
              ) : (
                <span className="text-slate-500">Unverified</span>
              )}
            </div>
          </div>

          {/* Commit Match */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase text-slate-500 flex items-center gap-1">
              <GitCommit className="w-3 h-3" /> Commit SHA Match
            </span>
            <div className="flex items-center gap-1.5 font-bold">
              {provenance?.commit_matched ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-300">Exact Match</span>
                </>
              ) : (
                <span className="text-slate-500">No SHA Attested</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Reasons & Transparency Details */}
      {provenance?.reasons && provenance.reasons.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
          <h3 className="text-slate-200 font-bold text-sm">Verification Reasons &amp; Logs</h3>
          <ul className="space-y-2">
            {provenance.reasons.map((reason, i) => (
              <li key={i} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex items-start gap-2">
                <span className="text-cyan-400 font-bold">•</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Source & Build Identity Details */}
      <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
        <h3 className="text-slate-200 font-bold text-sm">Attestation Metadata</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div className="p-3 rounded bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Build Signer</span>
            <span className="text-slate-300 break-all">{provenance?.build_signer || "None (Unsigned)"}</span>
          </div>
          <div className="p-3 rounded bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Source Repository</span>
            <span className="text-slate-300 break-all">{provenance?.source_repository || "Unknown"}</span>
          </div>
          <div className="p-3 rounded bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Attested Commit SHA</span>
            <span className="text-slate-300 break-all">{provenance?.build_commit_sha || "None"}</span>
          </div>
          <div className="p-3 rounded bg-slate-950 border border-slate-800">
            <span className="text-slate-500 block text-[10px] uppercase">Package Integrity (SHA-512)</span>
            <span className="text-slate-300 break-all">
              {provenance?.package_integrity_match !== undefined
                ? provenance.package_integrity_match
                  ? "Matched Registry Manifest"
                  : "Mismatch Detected"
                : "Evaluated"}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

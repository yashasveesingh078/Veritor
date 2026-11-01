"use client";

import React, { useState, useEffect, useRef } from "react";
import { Navbar } from "../components/Navbar";
import { LandingHero } from "../components/LandingHero";
import { ScannerForm } from "../components/ScannerForm";
import { ProgressTracker } from "../components/ProgressTracker";
import { ReportDashboard } from "../components/ReportDashboard";
import { FileExplorer } from "../components/FileExplorer";
import { DiffViewer } from "../components/DiffViewer";
import { FindingsViewer } from "../components/FindingsViewer";
import { ProvenanceCard } from "../components/ProvenanceCard";
import { AIInvestigatorView } from "../components/AIInvestigatorView";
import { ScanHistoryView } from "../components/ScanHistoryView";
import { WatchlistView } from "../components/WatchlistView";
import { SettingsView } from "../components/SettingsView";
import {
  createScan,
  getFileDiff,
  getScanFiles,
  getScanReport,
  getScanStatus,
} from "../lib/api";
import {
  addToWatchlist,
  getScanHistory,
  getWatchlist,
  saveScanToHistory,
} from "../lib/storage";
import {
  Ecosystem,
  FileDiffItem,
  PackageFileItem,
  ScanHistoryItem,
  ScanReportResponse,
  ScanRequest,
  ScanStatusResponse,
  WatchlistItem,
} from "../lib/types";
import { AlertOctagon } from "lucide-react";

export default function Home() {
  const [activeTab, setActiveTab] = useState<
    "scanner" | "report" | "history" | "watchlist" | "settings"
  >("scanner");
  const [activeReportTab, setActiveReportTab] = useState<
    "overview" | "files" | "findings" | "provenance" | "ai"
  >("overview");

  // Form input state
  const [formParams, setFormParams] = useState<{
    ecosystem: Ecosystem;
    packageName: string;
    version: string;
  }>({
    ecosystem: "npm",
    packageName: "",
    version: "",
  });

  // Current active scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const [scanReport, setScanReport] = useState<ScanReportResponse | null>(null);
  const [files, setFiles] = useState<PackageFileItem[]>([]);
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [selectedDiff, setSelectedDiff] = useState<FileDiffItem | null>(null);
  const [isDiffLoading, setIsDiffLoading] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);

  // Persisted state initialized lazily
  const [history, setHistory] = useState<ScanHistoryItem[]>(() => getScanHistory());
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>(() => getWatchlist());

  // Polling ref
  const pollingRef = useRef<NodeJS.Timeout | null>(null);

  // Listen for storage events across tabs or components
  useEffect(() => {
    const handleHistoryUpdate = () => setHistory(getScanHistory());
    const handleWatchlistUpdate = () => setWatchlist(getWatchlist());

    window.addEventListener("veritor_history_updated", handleHistoryUpdate);
    window.addEventListener("veritor_watchlist_updated", handleWatchlistUpdate);

    return () => {
      window.removeEventListener("veritor_history_updated", handleHistoryUpdate);
      window.removeEventListener("veritor_watchlist_updated", handleWatchlistUpdate);
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  // Poll scan status until complete or failed
  const pollStatus = (scanId: string) => {
    if (pollingRef.current) clearInterval(pollingRef.current);

    pollingRef.current = setInterval(async () => {
      try {
        const statusRes = await getScanStatus(scanId);
        setScanStatus(statusRes);

        if (statusRes.status === "completed") {
          if (pollingRef.current) clearInterval(pollingRef.current);
          setIsScanning(false);
          await loadCompletedScan(scanId);
        } else if (statusRes.status === "failed") {
          if (pollingRef.current) clearInterval(pollingRef.current);
          setIsScanning(false);
          setScanError(statusRes.error || "Package verification pipeline failed.");
        }
      } catch (err: unknown) {
        if (pollingRef.current) clearInterval(pollingRef.current);
        setIsScanning(false);
        setScanError(err instanceof Error ? err.message : "Failed to poll scan status.");
      }
    }, 1000);
  };

  // Load all artifacts once scan completes
  const loadCompletedScan = async (scanId: string) => {
    try {
      const [reportRes, filesRes] = await Promise.all([
        getScanReport(scanId),
        getScanFiles(scanId),
      ]);

      setScanReport(reportRes);
      setFiles(filesRes.files || []);

      // Persist to history
      saveScanToHistory({
        scan_id: scanId,
        ecosystem: reportRes.ecosystem,
        package_name: reportRes.package_name,
        version: reportRes.version,
        status: reportRes.status,
        risk_score: reportRes.risk?.score,
        risk_level: reportRes.risk?.level,
        timestamp: new Date().toISOString(),
        duration_seconds: reportRes.duration_seconds,
      });

      // Automatically select the first suspicious or modified file if any
      const candidate =
        filesRes.files.find((f: PackageFileItem) => f.classification === "SUSPICIOUS") ||
        filesRes.files.find((f: PackageFileItem) => f.status === "ADDED") ||
        filesRes.files.find((f: PackageFileItem) => f.status === "MODIFIED") ||
        filesRes.files[0];

      if (candidate) {
        setSelectedFilePath(candidate.path);
        loadDiff(scanId, candidate.path);
      }

      setActiveTab("report");
      setActiveReportTab("overview");
    } catch (err: unknown) {
      setScanError(err instanceof Error ? err.message : "Failed to load scan report.");
    }
  };

  // Load single file diff
  const loadDiff = async (scanId: string, path: string) => {
    setIsDiffLoading(true);
    try {
      const diffRes = await getFileDiff(scanId, path);
      setSelectedDiff(diffRes);
    } catch (err) {
      console.error("Diff load error:", err);
      setSelectedDiff(null);
    } finally {
      setIsDiffLoading(false);
    }
  };

  // Handle new scan submit
  const handleStartScan = async (request: ScanRequest) => {
    setScanError(null);
    setScanReport(null);
    setFiles([]);
    setSelectedFilePath(null);
    setSelectedDiff(null);
    setIsScanning(true);
    setActiveTab("scanner");

    try {
      const initRes = await createScan(request);
      setScanStatus({
        scan_id: initRes.scan_id,
        ecosystem: initRes.ecosystem,
        package_name: initRes.package_name,
        version: initRes.version,
        status: "accepted",
        stage: "queued",
        progress_percent: 5,
        message: "Scan requested and queued...",
        created_at: new Date().toISOString(),
      });

      pollStatus(initRes.scan_id);
    } catch (err: unknown) {
      setIsScanning(false);
      setScanError(err instanceof Error ? err.message : "Failed to initialize package scan.");
    }
  };

  // Select file from file explorer or findings
  const handleSelectFile = (path: string) => {
    setSelectedFilePath(path);
    if (scanReport) {
      loadDiff(scanReport.scan_id, path);
      if (activeReportTab !== "files") {
        setActiveReportTab("files");
      }
    }
  };

  // Quick fill from sample selector
  const handleSelectSample = (ecosystem: Ecosystem, name: string, version: string) => {
    setFormParams({ ecosystem, packageName: name, version });
    setActiveTab("scanner");
  };

  // Trigger scan from history
  const handleSelectHistoryScan = async (item: ScanHistoryItem) => {
    setScanError(null);
    try {
      await loadCompletedScan(item.scan_id);
      setActiveTab("report");
    } catch {
      // If report not in backend memory, re-populate scanner form
      setFormParams({
        ecosystem: item.ecosystem,
        packageName: item.package_name,
        version: item.version,
      });
      setActiveTab("scanner");
    }
  };

  // Add to watchlist handler
  const handleAddToWatchlist = (ecosystem: Ecosystem, packageName: string) => {
    addToWatchlist({
      ecosystem,
      package_name: packageName,
      notes: "Monitored dependency",
    });
    setWatchlist(getWatchlist());
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        hasActiveReport={!!scanReport}
        historyCount={history.length}
        watchlistCount={watchlist.length}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Error notification banner */}
        {scanError && (
          <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 font-mono text-xs flex items-center justify-between gap-3 shadow-lg">
            <div className="flex items-center gap-2.5">
              <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0" />
              <span>{scanError}</span>
            </div>
            <button
              onClick={() => setScanError(null)}
              className="text-rose-400 hover:text-rose-200 text-xs uppercase font-bold"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* TAB: SCANNER */}
        {activeTab === "scanner" && (
          <div className="space-y-6">
            {!isScanning && !scanStatus && (
              <LandingHero onSelectSample={handleSelectSample} />
            )}

            <ScannerForm
              key={`${formParams.ecosystem}-${formParams.packageName}-${formParams.version}`}
              onSubmit={handleStartScan}
              isLoading={isScanning}
              initialEcosystem={formParams.ecosystem}
              initialPackage={formParams.packageName}
              initialVersion={formParams.version}
              onAddToWatchlist={handleAddToWatchlist}
            />

            {/* Real-time Progress Display */}
            {scanStatus && (
              <ProgressTracker
                status={scanStatus}
                onRetry={() => {
                  if (formParams.packageName && formParams.version) {
                    handleStartScan({
                      ecosystem: formParams.ecosystem,
                      package_name: formParams.packageName,
                      version: formParams.version,
                    });
                  }
                }}
              />
            )}
          </div>
        )}

        {/* TAB: REPORT */}
        {activeTab === "report" && scanReport && (
          <div className="space-y-6">
            <ReportDashboard
              report={scanReport}
              activeReportTab={activeReportTab}
              setActiveReportTab={setActiveReportTab}
            />

            {/* Sub-tab 1: Files & Diffs View */}
            {activeReportTab === "files" && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
                <div className="lg:col-span-1">
                  <FileExplorer
                    files={files}
                    selectedFilePath={selectedFilePath}
                    onSelectFile={handleSelectFile}
                  />
                </div>
                <div className="lg:col-span-2">
                  <DiffViewer
                    diff={selectedDiff}
                    isLoading={isDiffLoading}
                    filePath={selectedFilePath || "No file selected"}
                  />
                </div>
              </div>
            )}

            {/* Sub-tab 2: Security Findings View */}
            {activeReportTab === "findings" && (
              <FindingsViewer
                findings={scanReport.security?.findings || []}
                gaps={scanReport.security?.gaps || []}
                aiExplanations={scanReport.ai?.explanations || []}
                onSelectFile={handleSelectFile}
              />
            )}

            {/* Sub-tab 3: Provenance View */}
            {activeReportTab === "provenance" && (
              <ProvenanceCard
                provenance={scanReport.provenance}
                packageName={scanReport.package_name}
                version={scanReport.version}
              />
            )}

            {/* Sub-tab 4: AI Investigator View */}
            {activeReportTab === "ai" && (
              <AIInvestigatorView
                ai={scanReport.ai}
                packageName={scanReport.package_name}
                version={scanReport.version}
              />
            )}
          </div>
        )}

        {/* TAB: HISTORY */}
        {activeTab === "history" && (
          <ScanHistoryView
            history={history}
            onSelectScan={handleSelectHistoryScan}
            onClearHistory={() => setHistory([])}
            onScanNew={() => setActiveTab("scanner")}
          />
        )}

        {/* TAB: WATCHLIST */}
        {activeTab === "watchlist" && (
          <WatchlistView
            watchlist={watchlist}
            onTriggerScan={(ecosystem, pkgName) => {
              setFormParams({ ecosystem, packageName: pkgName, version: "" });
              setActiveTab("scanner");
            }}
            onRefresh={() => setWatchlist(getWatchlist())}
          />
        )}

        {/* TAB: SETTINGS */}
        {activeTab === "settings" && <SettingsView />}
      </main>

      {/* Cyber Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 text-center text-xs font-mono text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-300">Veritor</span>
            <span>— Supply Chain Integrity Analysis Engine</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400">
            <span>Deterministic Scoring</span>
            <span>•</span>
            <span>Sigstore Cryptography</span>
            <span>•</span>
            <span>AST Static Walk</span>
            <span>•</span>
            <span>Ollama AI</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

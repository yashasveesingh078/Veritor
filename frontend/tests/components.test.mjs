import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const srcDir = path.join(rootDir, "src");

test("all required frontend components exist and export functional elements", () => {
  const components = [
    { file: "components/Navbar.tsx", match: /export function Navbar/ },
    { file: "components/LandingHero.tsx", match: /export function LandingHero/ },
    { file: "components/ScannerForm.tsx", match: /export function ScannerForm/ },
    { file: "components/ProgressTracker.tsx", match: /export function ProgressTracker/ },
    { file: "components/ReportDashboard.tsx", match: /export function ReportDashboard/ },
    { file: "components/FileExplorer.tsx", match: /export function FileExplorer/ },
    { file: "components/DiffViewer.tsx", match: /export function DiffViewer/ },
    { file: "components/FindingsViewer.tsx", match: /export function FindingsViewer/ },
    { file: "components/ProvenanceCard.tsx", match: /export function ProvenanceCard/ },
    { file: "components/AIInvestigatorView.tsx", match: /export function AIInvestigatorView/ },
    { file: "components/ScanHistoryView.tsx", match: /export function ScanHistoryView/ },
    { file: "components/WatchlistView.tsx", match: /export function WatchlistView/ },
    { file: "components/SettingsView.tsx", match: /export function SettingsView/ },
  ];

  for (const comp of components) {
    const fullPath = path.join(srcDir, comp.file);
    assert.ok(fs.existsSync(fullPath), `Component file must exist: ${comp.file}`);
    const content = fs.readFileSync(fullPath, "utf8");
    assert.match(content, comp.match, `Component must define export in ${comp.file}`);
  }
});

test("API client defines all required FastAPI endpoints", () => {
  const apiPath = path.join(srcDir, "lib", "api.ts");
  assert.ok(fs.existsSync(apiPath), "lib/api.ts must exist");
  const content = fs.readFileSync(apiPath, "utf8");

  assert.match(content, /export async function createScan/, "Must export createScan");
  assert.match(content, /export async function getScanStatus/, "Must export getScanStatus");
  assert.match(content, /export async function getScanReport/, "Must export getScanReport");
  assert.match(content, /export async function getScanFiles/, "Must export getScanFiles");
  assert.match(content, /export async function getFileDiff/, "Must export getFileDiff");
  assert.match(content, /export async function getScanFindings/, "Must export getScanFindings");
  assert.match(content, /export async function checkBackendHealth/, "Must export checkBackendHealth");
  assert.match(content, /export async function checkOllamaConnection/, "Must export checkOllamaConnection");
});

test("Storage utilities manage history and watchlist persistence", () => {
  const storagePath = path.join(srcDir, "lib", "storage.ts");
  assert.ok(fs.existsSync(storagePath), "lib/storage.ts must exist");
  const content = fs.readFileSync(storagePath, "utf8");

  assert.match(content, /export function getScanHistory/, "Must export getScanHistory");
  assert.match(content, /export function saveScanToHistory/, "Must export saveScanToHistory");
  assert.match(content, /export function clearScanHistory/, "Must export clearScanHistory");
  assert.match(content, /export function getWatchlist/, "Must export getWatchlist");
  assert.match(content, /export function addToWatchlist/, "Must export addToWatchlist");
  assert.match(content, /export function removeFromWatchlist/, "Must export removeFromWatchlist");
});

test("Type declarations cover all backend models and schemas", () => {
  const typesPath = path.join(srcDir, "lib", "types.ts");
  assert.ok(fs.existsSync(typesPath), "lib/types.ts must exist");
  const content = fs.readFileSync(typesPath, "utf8");

  assert.match(content, /export type Ecosystem/, "Must define Ecosystem");
  assert.match(content, /export type ScanState/, "Must define ScanState");
  assert.match(content, /export type ScanStage/, "Must define ScanStage");
  assert.match(content, /export interface ScanRequest/, "Must define ScanRequest");
  assert.match(content, /export interface ScanReportResponse/, "Must define ScanReportResponse");
  assert.match(content, /export interface RiskAssessment/, "Must define RiskAssessment");
  assert.match(content, /export interface ProvenanceResult/, "Must define ProvenanceResult");
  assert.match(content, /export interface SecurityFinding/, "Must define SecurityFinding");
  assert.match(content, /export interface AIInvestigationResult/, "Must define AIInvestigationResult");
});

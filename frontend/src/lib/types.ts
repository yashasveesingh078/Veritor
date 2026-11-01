/**
 * Veritor TypeScript type definitions matching backend FastAPI schemas and models.
 */

export type Ecosystem = "npm" | "pypi";

export type ScanState = "accepted" | "running" | "completed" | "failed";

export type ScanStage =
  | "queued"
  | "fetching_metadata"
  | "downloading_artifact"
  | "resolving_source"
  | "extracting_package"
  | "downloading_source"
  | "extracting_source"
  | "comparing"
  | "security_scanning"
  | "checking_provenance"
  | "scoring_risk"
  | "ai_investigation"
  | "completed"
  | "failed";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type ProvenanceStatus =
  | "VERIFIED"
  | "NOT_VERIFIED"
  | "UNAVAILABLE"
  | "INVALID"
  | "UNCERTAIN";

export type ArtifactClassification =
  | "LIKELY_GENERATED"
  | "SUSPICIOUS"
  | "UNCERTAIN"
  | "SOURCE_AUTHENTIC";

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ScanRequest {
  ecosystem: Ecosystem;
  package_name: string;
  version: string;
}

export interface ScanResponse {
  scan_id: string;
  status: "accepted";
  ecosystem: Ecosystem;
  package_name: string;
  version: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  ecosystem: Ecosystem;
  package_name: string;
  version: string;
  status: ScanState;
  stage: ScanStage;
  progress_percent: number;
  message: string;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
}

export interface FileDiffItem {
  path: string;
  status: string; // "ADDED" | "MODIFIED" | "REMOVED" | "IDENTICAL"
  diff_status: string;
  unified?: string | null;
  added_lines?: number | null;
  removed_lines?: number | null;
  classification?: ArtifactClassification | null;
  explanation?: string | null;
}

export interface ScanDiffsResponse {
  scan_id: string;
  package_name: string;
  version: string;
  total_diffs: number;
  diffs: FileDiffItem[];
}

export interface PackageFileItem {
  path: string;
  status: "ADDED" | "MODIFIED" | "REMOVED" | "IDENTICAL" | string;
  diff_status?: string;
  classification?: ArtifactClassification;
  explanation?: string;
  evidence?: Record<string, unknown>;
  confidence?: number;
  package_size?: number;
  source_size?: number;
}

export interface ScanFilesSummary {
  total_package_files: number;
  total_source_files: number;
  added_files: number;
  modified_files: number;
  removed_files: number;
  identical_files: number;
  suspicious_files?: number;
  generated_files?: number;
  uncertain_files?: number;
}

export interface ScanFilesResponse {
  scan_id: string;
  package_name: string;
  version: string;
  summary?: ScanFilesSummary | null;
  files: PackageFileItem[];
}

export interface SecurityFinding {
  rule_id: string;
  path: string;
  line: number;
  severity: FindingSeverity;
  evidence: string;
  explanation: string;
  confidence: number;
  recommended_action: string;
}

export interface AnalysisGap {
  path: string;
  reason: string;
  severity?: string;
}

export interface RiskFactor {
  factor: string;
  points: number;
  details: string;
}

export interface RiskFloor {
  name: string;
  min_score: number;
  triggered: boolean;
  reason: string;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  factors: RiskFactor[];
  floors: RiskFloor[];
  recommendations: string[];
  limitations: string[];
  confidence: number;
  completeness: "COMPLETE" | "PARTIAL" | string;
}

export interface ProvenanceClaim {
  key: string;
  value: string;
  verified: boolean;
}

export interface ProvenanceResult {
  status: ProvenanceStatus;
  sigstore_verified?: boolean;
  build_signer?: string;
  build_runner?: string;
  commit_matched?: boolean;
  repository_matched?: boolean;
  source_repository?: string;
  build_commit_sha?: string;
  package_integrity_match?: boolean;
  reasons: string[];
  claims?: ProvenanceClaim[];
}

export interface AIExplanationItem {
  finding_rule_id: string;
  file_path: string;
  assessment: string;
  reason: string;
  false_positive_likelihood: "LOW" | "MEDIUM" | "HIGH" | string;
}

export interface AIInvestigationResult {
  enabled: boolean;
  model?: string;
  triage_summary?: string | null;
  explanations?: AIExplanationItem[];
}

export interface SourceMatchInfo {
  repository_url?: string;
  resolved_commit?: string;
  match_confidence?: number;
  method?: string;
}

export interface PackageMetadataInfo {
  name: string;
  version: string;
  published_time?: string;
  tarball_url?: string;
  shasum?: string;
  integrity?: string;
  homepage?: string;
  license?: string;
}

export interface ScanReportResponse {
  scan_id: string;
  ecosystem: Ecosystem;
  package_name: string;
  version: string;
  status: ScanState;
  metadata?: PackageMetadataInfo | null;
  source_match?: SourceMatchInfo | null;
  comparison?: {
    summary: ScanFilesSummary;
    files: PackageFileItem[];
  } | null;
  security?: {
    findings: SecurityFinding[];
    gaps: AnalysisGap[];
    analysis_metadata?: Record<string, unknown>;
  } | null;
  provenance?: ProvenanceResult | null;
  risk?: RiskAssessment | null;
  ai?: AIInvestigationResult | null;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  duration_seconds?: number | null;
  error?: string | null;
}

export interface ScanFindingsResponse {
  scan_id: string;
  package_name: string;
  version: string;
  risk_score?: number | null;
  risk_level?: RiskLevel | null;
  findings: SecurityFinding[];
  ai_explanations: AIExplanationItem[];
  gaps: AnalysisGap[];
  factors: RiskFactor[];
  floors: RiskFloor[];
}

export interface ScanHistoryItem {
  scan_id: string;
  ecosystem: Ecosystem;
  package_name: string;
  version: string;
  status: ScanState;
  risk_score?: number | null;
  risk_level?: RiskLevel | null;
  timestamp: string;
  duration_seconds?: number | null;
}

export interface WatchlistItem {
  id: string;
  ecosystem: Ecosystem;
  package_name: string;
  added_at: string;
  notes?: string;
  last_scanned_version?: string;
  last_risk_score?: number | null;
  last_risk_level?: RiskLevel | null;
}

export interface HealthCheckResponse {
  status: string;
  ollama_connected?: boolean;
  ollama_models?: string[];
}

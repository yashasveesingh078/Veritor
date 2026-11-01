/**
 * Veritor API client for interacting with the FastAPI backend endpoints.
 */

import {
  FileDiffItem,
  HealthCheckResponse,
  ScanFilesResponse,
  ScanFindingsResponse,
  ScanReportResponse,
  ScanRequest,
  ScanResponse,
  ScanStatusResponse,
} from "./types";

const DEFAULT_API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export function getApiBaseUrl(): string {
  if (typeof window !== "undefined") {
    const saved = localStorage.getItem("veritor_api_base_url");
    if (saved && saved.trim()) {
      return saved.trim().replace(/\/+$/, "");
    }
  }
  return DEFAULT_API_URL.replace(/\/+$/, "");
}

export function setApiBaseUrl(url: string): void {
  if (typeof window !== "undefined") {
    if (!url || !url.trim()) {
      localStorage.removeItem("veritor_api_base_url");
    } else {
      localStorage.setItem("veritor_api_base_url", url.trim().replace(/\/+$/, ""));
    }
  }
}

export class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMsg = `API request failed with status ${res.status}`;
    let details: unknown = null;
    try {
      const data = await res.json();
      if (data && typeof data === "object") {
        if ("detail" in data && typeof data.detail === "string") {
          errorMsg = data.detail;
        } else if ("error" in data && data.error && typeof data.error === "object" && "message" in data.error) {
          errorMsg = String(data.error.message);
          details = data.error.details || null;
        } else if ("message" in data && typeof data.message === "string") {
          errorMsg = data.message;
        }
      }
    } catch {
      // Body not JSON
    }
    throw new ApiError(errorMsg, res.status, details);
  }
  return res.json() as Promise<T>;
}

/**
 * Trigger a new scan.
 * POST /api/v1/scans
 */
export async function createScan(request: ScanRequest): Promise<ScanResponse> {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/v1/scans`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
  return handleResponse<ScanResponse>(res);
}

/**
 * Poll current status and progress of a scan.
 * GET /api/v1/scans/{scan_id}
 */
export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/v1/scans/${encodeURIComponent(scanId)}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });
  return handleResponse<ScanStatusResponse>(res);
}

/**
 * Fetch full integrity report once scan has completed.
 * GET /api/v1/scans/{scan_id}/report
 */
export async function getScanReport(scanId: string): Promise<ScanReportResponse> {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/v1/scans/${encodeURIComponent(scanId)}/report`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });
  return handleResponse<ScanReportResponse>(res);
}

/**
 * Fetch file list and generated classifications.
 * GET /api/v1/scans/{scan_id}/files
 */
export async function getScanFiles(scanId: string): Promise<ScanFilesResponse> {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/v1/scans/${encodeURIComponent(scanId)}/files`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });
  return handleResponse<ScanFilesResponse>(res);
}

/**
 * Fetch specific file diff by file path or identifier.
 * GET /api/v1/scans/{scan_id}/files/{file_id}/diff
 */
export async function getFileDiff(scanId: string, filePath: string): Promise<FileDiffItem> {
  const baseUrl = getApiBaseUrl();
  // Ensure filePath slashes are preserved or properly encoded for FastAPI path parameter
  const cleanPath = filePath.replace(/^\/+/, "");
  const res = await fetch(`${baseUrl}/api/v1/scans/${encodeURIComponent(scanId)}/files/${cleanPath}/diff`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });
  return handleResponse<FileDiffItem>(res);
}

/**
 * Fetch security findings and AI explanations.
 * GET /api/v1/scans/{scan_id}/findings
 */
export async function getScanFindings(scanId: string): Promise<ScanFindingsResponse> {
  const baseUrl = getApiBaseUrl();
  const res = await fetch(`${baseUrl}/api/v1/scans/${encodeURIComponent(scanId)}/findings`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });
  return handleResponse<ScanFindingsResponse>(res);
}

/**
 * Check backend health status.
 * GET /health
 */
export async function checkBackendHealth(): Promise<HealthCheckResponse> {
  const baseUrl = getApiBaseUrl();
  try {
    const res = await fetch(`${baseUrl}/health`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });
    if (!res.ok) {
      return { status: "unhealthy" };
    }
    const data = await res.json();
    return { status: data.status || "ok" };
  } catch {
    return { status: "disconnected" };
  }
}

/**
 * Check local Ollama connection directly or check models available.
 */
export async function checkOllamaConnection(ollamaUrl = "http://127.0.0.1:11434"): Promise<{
  connected: boolean;
  models: string[];
}> {
  try {
    const res = await fetch(`${ollamaUrl}/api/tags`, {
      method: "GET",
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) {
      return { connected: false, models: [] };
    }
    const data = await res.json();
    const models = Array.isArray(data.models)
      ? data.models.map((m: { name?: string }) => m.name || "").filter(Boolean)
      : [];
    return { connected: true, models };
  } catch {
    return { connected: false, models: [] };
  }
}

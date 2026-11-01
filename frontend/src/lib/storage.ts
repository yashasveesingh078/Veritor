/**
 * Storage helpers for local scan history and monitored package watchlist.
 */

import { ScanHistoryItem, WatchlistItem } from "./types";

const HISTORY_KEY = "veritor_scan_history_v1";
const WATCHLIST_KEY = "veritor_watchlist_v1";
const MAX_HISTORY = 50;

export function getScanHistory(): ScanHistoryItem[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveScanToHistory(item: ScanHistoryItem): void {
  if (typeof window === "undefined") return;
  try {
    const current = getScanHistory();
    // Deduplicate by scan_id
    const filtered = current.filter((h) => h.scan_id !== item.scan_id);
    const updated = [item, ...filtered].slice(0, MAX_HISTORY);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event("veritor_history_updated"));
  } catch {
    // LocalStorage quota or disabled
  }
}

export function clearScanHistory(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(HISTORY_KEY);
    window.dispatchEvent(new Event("veritor_history_updated"));
  } catch {
    // Ignore
  }
}

export function getWatchlist(): WatchlistItem[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(WATCHLIST_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function addToWatchlist(item: Omit<WatchlistItem, "id" | "added_at">): WatchlistItem {
  const current = getWatchlist();
  const existing = current.find(
    (w) => w.ecosystem === item.ecosystem && w.package_name.toLowerCase() === item.package_name.toLowerCase()
  );
  if (existing) {
    return existing;
  }
  const newItem: WatchlistItem = {
    ...item,
    id: `${item.ecosystem}:${item.package_name}:${Date.now()}`,
    added_at: new Date().toISOString(),
  };
  const updated = [newItem, ...current];
  if (typeof window !== "undefined") {
    try {
      localStorage.setItem(WATCHLIST_KEY, JSON.stringify(updated));
      window.dispatchEvent(new Event("veritor_watchlist_updated"));
    } catch {
      // Ignore
    }
  }
  return newItem;
}

export function removeFromWatchlist(id: string): void {
  if (typeof window === "undefined") return;
  try {
    const current = getWatchlist();
    const updated = current.filter((w) => w.id !== id);
    localStorage.setItem(WATCHLIST_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event("veritor_watchlist_updated"));
  } catch {
    // Ignore
  }
}

export function updateWatchlistItem(
  id: string,
  updates: Partial<Omit<WatchlistItem, "id" | "ecosystem" | "package_name">>
): void {
  if (typeof window === "undefined") return;
  try {
    const current = getWatchlist();
    const updated = current.map((w) => (w.id === id ? { ...w, ...updates } : w));
    localStorage.setItem(WATCHLIST_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event("veritor_watchlist_updated"));
  } catch {
    // Ignore
  }
}

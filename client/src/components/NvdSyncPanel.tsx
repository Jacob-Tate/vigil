import { useState } from "react";
import toast from "react-hot-toast";
import { useNvdStatus } from "../hooks/useNvdStatus";
import { triggerNvdSync } from "../api/client";
import { formatDistanceToNow } from "date-fns";

export default function NvdSyncPanel() {
  const { status, refetch } = useNvdStatus();
  const [syncing, setSyncing] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const totalCves = status?.feedStates.reduce(
    (sum, f) => sum + (f.total_cves ?? 0),
    0
  ) ?? 0;

  const sortedImports = status?.feedStates
    .map((f) => f.imported_at)
    .filter((d): d is string => d !== null)
    .sort() ?? [];
  const lastImport = sortedImports[sortedImports.length - 1];

  const handleSync = async () => {
    if (syncing || status?.isImporting) return;
    if (
      !confirm(
        "This will download the full NVD dataset (~180 MB). This may take several minutes. Continue?"
      )
    )
      return;
    setSyncing(true);
    try {
      await triggerNvdSync();
      toast.success("NVD sync started in background");
      await refetch();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Sync failed");
    } finally {
      setSyncing(false);
    }
  };

  const isImporting = status?.isImporting ?? false;

  return (
    <div className="bg-white border border-gray-200 rounded-xl mb-6">
      {/* Header row */}
      <div className="flex items-center justify-between px-4 py-3">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setExpanded((e) => !e)}
            className="text-sm font-medium text-gray-700 flex items-center gap-1.5 hover:text-gray-900"
          >
            <svg
              className={`w-3.5 h-3.5 transition-transform ${expanded ? "rotate-90" : ""}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 5l7 7-7 7"
              />
            </svg>
            NVD Database
          </button>

          {isImporting ? (
            <span className="text-xs text-blue-600 bg-blue-50 px-2 py-0.5 rounded-full font-medium animate-pulse">
              Importing {status?.currentFeed ?? "…"} ({status?.feedsDone}/{status?.feedsTotal})
            </span>
          ) : totalCves > 0 ? (
            <span className="text-xs text-gray-500">
              {totalCves.toLocaleString()} CVEs
              {lastImport ? ` · synced ${formatDistanceToNow(new Date(lastImport), { addSuffix: true })}` : ""}
            </span>
          ) : (
            <span className="text-xs text-amber-600 bg-amber-50 px-2 py-0.5 rounded-full font-medium">
              No data — sync required
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          {isImporting && (
            <div className="w-32 h-1.5 bg-gray-100 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 transition-all"
                style={{
                  width: `${status?.feedsTotal ? Math.round((status.feedsDone / status.feedsTotal) * 100) : 0}%`,
                }}
              />
            </div>
          )}
          <button
            onClick={() => void handleSync()}
            disabled={syncing || isImporting}
            className="text-xs bg-gray-900 text-white px-3 py-1.5 rounded-lg font-medium hover:bg-gray-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isImporting ? "Syncing…" : "Sync All"}
          </button>
        </div>
      </div>

      {/* Error banner */}
      {status?.error && (
        <div className="px-4 pb-3 text-xs text-red-600">
          Last sync error: {status.error}
        </div>
      )}

      {/* Expandable feed state table */}
      {expanded && status && (
        <div className="border-t border-gray-100 px-4 pb-3 pt-2 max-h-64 overflow-y-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-400 text-left">
                <th className="pb-1 font-medium">Feed</th>
                <th className="pb-1 font-medium text-right">CVEs</th>
                <th className="pb-1 font-medium text-right">Last imported</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {status.feedStates.map((f) => (
                <tr key={f.feed_name}>
                  <td className="py-0.5 text-gray-700 font-mono">{f.feed_name}</td>
                  <td className="py-0.5 text-right text-gray-500">
                    {f.total_cves?.toLocaleString() ?? "—"}
                  </td>
                  <td className="py-0.5 text-right text-gray-400">
                    {f.imported_at
                      ? formatDistanceToNow(new Date(f.imported_at), { addSuffix: true })
                      : "never"}
                  </td>
                </tr>
              ))}
              {status.feedStates.length === 0 && (
                <tr>
                  <td colSpan={3} className="py-2 text-center text-gray-400">
                    No feeds imported yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

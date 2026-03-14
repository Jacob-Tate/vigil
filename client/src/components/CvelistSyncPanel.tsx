import { useState } from "react";
import toast from "react-hot-toast";
import { useCvelistStatus } from "../hooks/useCvelistStatus";
import { triggerCvelistSync } from "../api/client";
import { formatDistanceToNow } from "date-fns";
import { useAuth } from "../hooks/useAuth";

function SyncProgressBar({ done, total, message }: { done: number; total: number; message: string }) {
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  return (
    <div className="mt-1.5 space-y-1">
      <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400">
        <span className="truncate max-w-[70%]">{message}</span>
        <span>{total > 0 ? `${pct}%` : "…"}</span>
      </div>
      <div className="w-full bg-gray-100 dark:bg-gray-700 rounded-full h-1.5 overflow-hidden">
        <div
          className="bg-blue-500 h-1.5 rounded-full transition-all duration-500"
          style={{ width: total > 0 ? `${pct}%` : "100%", animation: total === 0 ? "pulse 1.5s ease-in-out infinite" : undefined }}
        />
      </div>
    </div>
  );
}

export default function CvelistSyncPanel() {
  const { status, refetch } = useCvelistStatus();
  const { isAdmin } = useAuth();
  const [syncing, setSyncing] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const isSyncing = status?.is_syncing ?? false;
  const hasProgress = isSyncing && status?.stage_message != null;

  const handleSync = async () => {
    if (syncing || isSyncing) return;
    setSyncing(true);
    try {
      await triggerCvelistSync();
      toast.success("CVE list sync started in background");
      await refetch();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "CVE list sync failed");
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl mb-6">
      {/* Header row */}
      <div className="flex items-center justify-between px-4 py-3">
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <button
            onClick={() => setExpanded((e) => !e)}
            className="text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-1.5 hover:text-gray-900 dark:hover:text-white shrink-0"
          >
            <svg
              className={`w-3.5 h-3.5 transition-transform ${expanded ? "rotate-90" : ""}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
            CVE Program (cvelistV5)
          </button>

          {isSyncing ? (
            <span className="text-xs text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 px-2 py-0.5 rounded-full font-medium animate-pulse shrink-0">
              Syncing…
            </span>
          ) : (status?.total ?? 0) > 0 ? (
            <span className="text-xs text-gray-500 dark:text-gray-400 truncate">
              {status!.total.toLocaleString()} CVEs
              {status!.rejected_count > 0 && (
                <span className="ml-1 text-red-500 dark:text-red-400">
                  · {status!.rejected_count.toLocaleString()} rejected
                </span>
              )}
              {status!.last_synced_at
                ? ` · synced ${formatDistanceToNow(new Date(status!.last_synced_at), { addSuffix: true })}`
                : ""}
            </span>
          ) : (
            <span className="text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 px-2 py-0.5 rounded-full font-medium shrink-0">
              No data — sync required
            </span>
          )}
        </div>

        {isAdmin && (
          <button
            onClick={() => void handleSync()}
            disabled={syncing || isSyncing}
            className="ml-3 text-xs bg-gray-900 dark:bg-gray-700 text-white px-3 py-1.5 rounded-lg font-medium hover:bg-gray-700 dark:hover:bg-gray-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            {isSyncing ? "Syncing…" : "Sync CVE List"}
          </button>
        )}
      </div>

      {/* Live progress bar (shown while syncing) */}
      {hasProgress && (
        <div className="px-4 pb-3">
          <SyncProgressBar
            done={status!.files_done ?? 0}
            total={status!.files_total ?? 0}
            message={status!.stage_message!}
          />
        </div>
      )}

      {/* Expandable details */}
      {expanded && status && (
        <div className="border-t border-gray-100 dark:border-gray-700 px-4 pb-3 pt-2">
          <table className="w-full text-xs">
            <tbody className="divide-y divide-gray-50 dark:divide-gray-700">
              <tr>
                <td className="py-0.5 text-gray-500 dark:text-gray-400">Total CVEs</td>
                <td className="py-0.5 text-right text-gray-700 dark:text-gray-300 font-medium">
                  {status.total.toLocaleString()}
                </td>
              </tr>
              <tr>
                <td className="py-0.5 text-gray-500 dark:text-gray-400">Rejected</td>
                <td className={`py-0.5 text-right font-medium ${status.rejected_count > 0 ? "text-red-600 dark:text-red-400" : "text-gray-700 dark:text-gray-300"}`}>
                  {status.rejected_count.toLocaleString()}
                </td>
              </tr>
              {status.last_repo_version && (
                <tr>
                  <td className="py-0.5 text-gray-500 dark:text-gray-400">Repo commit</td>
                  <td className="py-0.5 text-right text-gray-700 dark:text-gray-300 font-mono">
                    {status.last_repo_version.slice(0, 8)}
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

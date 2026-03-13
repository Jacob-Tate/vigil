import { useState } from "react";
import toast from "react-hot-toast";
import { useCvelistStatus } from "../hooks/useCvelistStatus";
import { triggerCvelistSync } from "../api/client";
import { formatDistanceToNow } from "date-fns";
import { useAuth } from "../hooks/useAuth";

export default function CvelistSyncPanel() {
  const { status, refetch } = useCvelistStatus();
  const { isAdmin } = useAuth();
  const [syncing, setSyncing] = useState(false);
  const [expanded, setExpanded] = useState(false);

  const isSyncing = status?.is_syncing ?? false;

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
        <div className="flex items-center gap-3">
          <button
            onClick={() => setExpanded((e) => !e)}
            className="text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center gap-1.5 hover:text-gray-900 dark:hover:text-white"
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
            CVE Program (cvelistV5)
          </button>

          {isSyncing ? (
            <span className="text-xs text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 px-2 py-0.5 rounded-full font-medium animate-pulse">
              Syncing…
            </span>
          ) : (status?.total ?? 0) > 0 ? (
            <span className="text-xs text-gray-500 dark:text-gray-400">
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
            <span className="text-xs text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 px-2 py-0.5 rounded-full font-medium">
              No data — sync required
            </span>
          )}
        </div>

        {isAdmin && (
          <button
            onClick={() => void handleSync()}
            disabled={syncing || isSyncing}
            className="text-xs bg-gray-900 dark:bg-gray-700 text-white px-3 py-1.5 rounded-lg font-medium hover:bg-gray-700 dark:hover:bg-gray-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSyncing ? "Syncing…" : "Sync CVE List"}
          </button>
        )}
      </div>

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

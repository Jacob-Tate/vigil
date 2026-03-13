import { useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { parseApiDate } from "../utils/date";
import toast from "react-hot-toast";
import { getServer, triggerCheck, resetBaseline } from "../api/client";
import { useChecks, useCheckStats } from "../hooks/useChecks";
import CheckHistoryTable from "../components/CheckHistoryTable";
import ResponseTimeChart from "../components/ResponseTimeChart";
import StatusBadge from "../components/StatusBadge";
import { Server } from "../types";
import { useEffect } from "react";

export default function ServerDetail() {
  const { id } = useParams<{ id: string }>();
  const serverId = parseInt(id ?? "0", 10);

  const [server, setServer] = useState<Server | null>(null);
  const [serverLoading, setServerLoading] = useState(true);
  const [page, setPage] = useState(1);

  const { checks, pagination, loading: checksLoading, refresh: refreshChecks } = useChecks(serverId, page);
  const { stats } = useCheckStats(serverId);

  const loadServer = useCallback(async () => {
    try {
      const s = await getServer(serverId);
      setServer(s);
    } catch {
      // handled below
    } finally {
      setServerLoading(false);
    }
  }, [serverId]);

  useEffect(() => {
    void loadServer();
  }, [loadServer]);

  const handleCheck = async () => {
    if (!server) return;
    try {
      await triggerCheck(server.id);
      toast.success("Check triggered");
      void loadServer();
      void refreshChecks();
    } catch {
      toast.error("Failed to trigger check");
    }
  };

  const handleResetBaseline = async () => {
    if (!server) return;
    if (!confirm("Clear the content baseline? The next check will set a new baseline without alerting.")) return;
    try {
      await resetBaseline(server.id);
      toast.success("Baseline cleared");
    } catch {
      toast.error("Failed to reset baseline");
    }
  };

  if (serverLoading) return <div className="text-center py-16 text-gray-400 dark:text-gray-500">Loading…</div>;
  if (!server) return <div className="text-center py-16 text-red-400">Server not found</div>;

  const lastCheck = server.last_check;
  const isUp = lastCheck ? lastCheck.is_up === 1 : null;
  const isDegraded =
    isUp === true &&
    lastCheck !== null &&
    lastCheck.response_time_ms !== null &&
    lastCheck.response_time_ms > server.response_time_threshold_ms;

  return (
    <div className="max-w-4xl mx-auto px-4 py-6">
      <div className="mb-6">
        <Link to="/http" className="text-sm text-gray-400 dark:text-gray-500 hover:text-blue-600 mb-2 inline-block">
          ← HTTP Monitor
        </Link>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{server.name}</h1>
            <a href={server.url} target="_blank" rel="noreferrer" className="text-sm text-gray-400 dark:text-gray-500 hover:text-blue-500">
              {server.url}
            </a>
          </div>
          <StatusBadge isUp={isUp} isDegraded={isDegraded} />
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Uptime</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">
            {stats?.uptime_pct != null ? `${stats.uptime_pct}%` : "—"}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Avg response</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">
            {stats?.avg_response_time_ms != null ? `${stats.avg_response_time_ms}ms` : "—"}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Total checks</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">{stats?.total_checks ?? "—"}</p>
        </div>
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Content changes</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">{stats?.content_changes ?? "—"}</p>
        </div>
      </div>

      {/* Response time chart */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4 mb-6">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Response time (last 50 checks)</h2>
        <ResponseTimeChart checks={checks} thresholdMs={server.response_time_threshold_ms} />
      </div>

      {/* Actions */}
      <div className="flex gap-2 mb-4">
        <button
          onClick={() => void handleCheck()}
          className="px-3 py-1.5 text-sm bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/50"
        >
          Check now
        </button>
        <button
          onClick={() => void handleResetBaseline()}
          className="px-3 py-1.5 text-sm bg-gray-50 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
        >
          Reset baseline
        </button>
        {lastCheck && (
          <span className="text-xs text-gray-400 dark:text-gray-500 self-center ml-auto">
            Last checked {formatDistanceToNow(parseApiDate(lastCheck.checked_at), { addSuffix: true })}
          </span>
        )}
      </div>

      {/* Check history */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Check history</h2>
        {checksLoading ? (
          <p className="text-gray-400 dark:text-gray-500 text-sm text-center py-4">Loading…</p>
        ) : (
          <CheckHistoryTable
            checks={checks}
            serverId={serverId}
            responseThresholdMs={server.response_time_threshold_ms}
          />
        )}

        {pagination && pagination.pages > 1 && (
          <div className="flex items-center justify-between mt-4 pt-3 border-t border-gray-100 dark:border-gray-700">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              className="text-sm px-3 py-1 rounded border dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40 dark:text-gray-300"
            >
              Previous
            </button>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Page {page} of {pagination.pages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(pagination.pages, p + 1))}
              disabled={page === pagination.pages}
              className="text-sm px-3 py-1 rounded border dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-40 dark:text-gray-300"
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

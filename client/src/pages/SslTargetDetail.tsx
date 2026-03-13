import { useState, useEffect, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import toast from "react-hot-toast";
import { getSslTarget, triggerSslCheck, getSslTargetCertUrl } from "../api/client";
import { useSslChecks, useSslCheckStats } from "../hooks/useSslChecks";
import SslCertPanel from "../components/SslCertPanel";
import { SslTarget } from "../types";

export default function SslTargetDetail() {
  const { id } = useParams<{ id: string }>();
  const targetId = parseInt(id ?? "0", 10);

  const [target, setTarget] = useState<SslTarget | null>(null);
  const [targetLoading, setTargetLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [page, setPage] = useState(1);

  const { checks, pagination, loading: checksLoading, refetch: refreshChecks } = useSslChecks(targetId, page);
  const { stats } = useSslCheckStats(targetId);

  const loadTarget = useCallback(async () => {
    try {
      const t = await getSslTarget(targetId);
      setTarget(t);
    } catch {
      // handled below
    } finally {
      setTargetLoading(false);
    }
  }, [targetId]);

  useEffect(() => {
    void loadTarget();
  }, [loadTarget]);

  const handleCheck = async () => {
    if (!target) return;
    setChecking(true);
    try {
      await triggerSslCheck(target.id);
      toast.success("Check complete");
      void loadTarget();
      void refreshChecks();
    } catch {
      toast.error("Failed to trigger check");
    } finally {
      setChecking(false);
    }
  };

  if (targetLoading) return <div className="text-center py-16 text-gray-400 dark:text-gray-500">Loading…</div>;
  if (!target) return <div className="text-center py-16 text-red-400">SSL target not found</div>;

  const lastCheck = target.last_check;

  return (
    <div className="max-w-4xl mx-auto px-4 py-6">
      {/* Breadcrumb + header */}
      <div className="mb-6">
        <Link to="/ssl" className="text-sm text-gray-400 dark:text-gray-500 hover:text-blue-600 mb-2 inline-block">
          ← SSL Monitor
        </Link>
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{target.name}</h1>
            <p className="text-sm text-gray-400 dark:text-gray-500 font-mono">
              {target.host}:{target.port}
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => void handleCheck()}
              disabled={checking}
              className="px-3 py-1.5 text-sm bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/50 disabled:opacity-50 transition-colors"
            >
              {checking ? "Checking…" : "Check now"}
            </button>
            <a
              href={getSslTargetCertUrl(target.id)}
              download={`${target.host}.pem`}
              className="px-3 py-1.5 text-sm bg-gray-50 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            >
              Download PEM
            </a>
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Days Remaining</p>
          <p className={`text-xl font-bold ${
            lastCheck?.days_remaining !== null && lastCheck?.days_remaining !== undefined
              ? lastCheck.days_remaining < 0
                ? "text-red-600 dark:text-red-400"
                : lastCheck.days_remaining <= 7
                ? "text-red-600 dark:text-red-400"
                : lastCheck.days_remaining <= 30
                ? "text-amber-600 dark:text-amber-400"
                : "text-green-600 dark:text-green-400"
              : "text-gray-900 dark:text-white"
          }`}>
            {lastCheck?.days_remaining !== null && lastCheck?.days_remaining !== undefined
              ? lastCheck.days_remaining
              : "—"}
          </p>
        </div>
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Total Checks</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">{stats?.total_checks ?? "—"}</p>
        </div>
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Cert Changes</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">{stats?.cert_changes ?? "—"}</p>
        </div>
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-xs text-gray-400 dark:text-gray-500">Check Errors</p>
          <p className="text-xl font-bold text-gray-900 dark:text-white">{stats?.error_checks ?? "—"}</p>
        </div>
      </div>

      {/* Certificate panel */}
      <div className="mb-6">
        <SslCertPanel
          check={lastCheck}
          loading={false}
          thresholdHours={target.expiry_threshold_hours}
        />
      </div>

      {/* Check history */}
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Check History</h2>
          {lastCheck && (
            <span className="text-xs text-gray-400 dark:text-gray-500">
              Last checked{" "}
              {formatDistanceToNow(new Date(lastCheck.checked_at), { addSuffix: true })}
            </span>
          )}
        </div>

        {checksLoading ? (
          <p className="text-gray-400 dark:text-gray-500 text-sm text-center py-4">Loading…</p>
        ) : checks.length === 0 ? (
          <p className="text-gray-400 dark:text-gray-500 text-sm text-center py-4">No checks yet</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-400 dark:text-gray-500 border-b border-gray-100 dark:border-gray-700">
                  <th className="pb-2 pr-4 font-medium">Time</th>
                  <th className="pb-2 pr-4 font-medium">Status</th>
                  <th className="pb-2 pr-4 font-medium">Days Left</th>
                  <th className="pb-2 pr-4 font-medium">TLS</th>
                  <th className="pb-2 pr-4 font-medium">Fingerprint</th>
                  <th className="pb-2 font-medium">Alert</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50 dark:divide-gray-700">
                {checks.map((check) => (
                  <tr key={check.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="py-2 pr-4 text-gray-500 dark:text-gray-400 whitespace-nowrap">
                      {formatDistanceToNow(new Date(check.checked_at), { addSuffix: true })}
                    </td>
                    <td className="py-2 pr-4">
                      {check.error ? (
                        <span className="text-xs bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 px-1.5 py-0.5 rounded-full">Error</span>
                      ) : (
                        <span className="text-xs bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 px-1.5 py-0.5 rounded-full">OK</span>
                      )}
                    </td>
                    <td className="py-2 pr-4 font-medium dark:text-gray-300">
                      {check.days_remaining !== null ? `${check.days_remaining}d` : "—"}
                    </td>
                    <td className="py-2 pr-4 text-gray-500 dark:text-gray-400">{check.tls_version ?? "—"}</td>
                    <td className="py-2 pr-4 font-mono text-gray-400 dark:text-gray-500 text-xs">
                      {check.fingerprint_sha256
                        ? check.fingerprint_sha256.slice(0, 16) + "…"
                        : "—"}
                    </td>
                    <td className="py-2">
                      {check.alert_type ? (
                        <span className="text-xs bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400 px-1.5 py-0.5 rounded-full">
                          {check.alert_type}
                        </span>
                      ) : (
                        <span className="text-gray-300 dark:text-gray-600">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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

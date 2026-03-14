import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import toast from "react-hot-toast";
import { useCveFindings } from "../hooks/useCveFindings";
import { getCveTarget, triggerCveCheck } from "../api/client";
import { useEffect } from "react";
import { CveTargetWithStats } from "../types";
import CveDetailModal from "../components/CveDetailModal";
import { formatDistanceToNow, format } from "date-fns";

function SeverityBadge({ severity }: { severity: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400",
    HIGH: "bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400",
    MEDIUM: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400",
    LOW: "bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400",
    NONE: "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400",
  };
  if (!severity) return <span className="text-gray-400 dark:text-gray-500">—</span>;
  const cls = map[severity.toUpperCase()] ?? "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400";
  return (
    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${cls}`}>
      {severity}
    </span>
  );
}

type SortKey = "cve_id" | "cvss_score" | "cvss_severity" | "published_at" | "found_at";
type SortDir = "asc" | "desc";


export default function CveTargetDetail() {
  const { id } = useParams<{ id: string }>();
  const targetId = parseInt(id ?? "0", 10);

  const [target, setTarget] = useState<CveTargetWithStats | null>(null);
  const [targetLoading, setTargetLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("cvss_score");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const { data, loading, refetch } = useCveFindings(targetId, page, 50, sortKey, sortDir);

  useEffect(() => {
    setTargetLoading(true);
    getCveTarget(targetId)
      .then((t) => setTarget(t))
      .catch(() => setTarget(null))
      .finally(() => setTargetLoading(false));
  }, [targetId]);

  const handleCheck = async () => {
    setChecking(true);
    try {
      const result = await triggerCveCheck(targetId);
      setTarget(result.target);
      await refetch();
      toast.success("Check complete");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Check failed");
    } finally {
      setChecking(false);
    }
  };

  if (targetLoading) {
    return (
      <div className="p-6 text-sm text-gray-400 dark:text-gray-500 text-center py-16">Loading…</div>
    );
  }

  if (!target) {
    return (
      <div className="p-6">
        <p className="text-red-600 dark:text-red-400">CVE target not found.</p>
        <Link to="/cve" className="text-sm text-blue-600 hover:underline mt-2 block">
          ← Back to CVE Monitor
        </Link>
      </div>
    );
  }

  const pagination = data?.pagination;

  const handleSort = (key: SortKey) => {
    setPage(1);
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "cvss_score" || key === "cvss_severity" ? "desc" : "asc");
    }
  };

  return (
    <div className="p-6">
      {/* Breadcrumb */}
      <Link to="/cve" className="text-sm text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 mb-4 block">
        ← CVE Monitor
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{target.name}</h1>
          <p className="text-sm font-mono text-gray-400 dark:text-gray-500 mt-0.5">
            {target.vendor ? `${target.vendor}:` : ""}
            {target.product}
            {target.version ? `:${target.version}` : " (any version)"}
          </p>
        </div>
        <button
          onClick={() => void handleCheck()}
          disabled={checking}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
        >
          {checking ? "Checking…" : "Check Now"}
        </button>
      </div>

      {/* Meta strip */}
      <div className="flex gap-6 mb-6 text-sm text-gray-500 dark:text-gray-400">
        <span>
          <span className="text-gray-700 dark:text-gray-300 font-medium">{target.findings_count}</span> CVEs found
        </span>
        <span>
          Min Alert CVSS:{" "}
          <span className="text-gray-700 dark:text-gray-300 font-medium">{target.min_alert_cvss_score}</span>
        </span>
        <span>
          {target.last_checked_at
            ? `Last checked ${formatDistanceToNow(new Date(target.last_checked_at), { addSuffix: true })}`
            : "Never checked"}
        </span>
      </div>

      {/* Findings table */}
      {loading && (
        <div className="text-sm text-gray-400 dark:text-gray-500 text-center py-8">Loading…</div>
      )}

      {!loading && (data?.data.length ?? 0) === 0 && (
        <div className="text-center py-12 text-gray-400 dark:text-gray-500">
          <p className="text-sm font-medium">No CVEs found yet</p>
          <p className="text-xs mt-1">
            Run a check or sync the NVD database to populate findings.
          </p>
        </div>
      )}

      {!loading && (data?.data.length ?? 0) > 0 && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-800 border-b border-gray-100 dark:border-gray-700">
              <tr>
                {(
                  [
                    { key: "cve_id", label: "CVE ID", align: "left" },
                    { key: "cvss_severity", label: "Severity", align: "left" },
                    { key: "cvss_score", label: "CVSS", align: "right" },
                    { key: "published_at", label: "Published", align: "left" },
                  ] as { key: SortKey; label: string; align: "left" | "right" }[]
                ).map(({ key, label, align }) => (
                  <th
                    key={key}
                    onClick={() => handleSort(key)}
                    className={`px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400 cursor-pointer select-none hover:text-gray-700 dark:hover:text-white whitespace-nowrap text-${align}`}
                  >
                    {label}
                    {sortKey === key ? (sortDir === "asc" ? " ↑" : " ↓") : " ↕"}
                  </th>
                ))}
                <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400 max-w-xs">Description</th>
                <th
                  onClick={() => handleSort("found_at")}
                  className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400 cursor-pointer select-none hover:text-gray-700 dark:hover:text-white whitespace-nowrap"
                >
                  Found{sortKey === "found_at" ? (sortDir === "asc" ? " ↑" : " ↓") : " ↕"}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50 dark:divide-gray-700">
              {(data?.data ?? []).map((finding) => (
                <tr
                  key={finding.id}
                  className="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                  onClick={() => setSelectedCveId(finding.cve_id)}
                >
                  <td className="px-4 py-3 font-mono text-blue-600 dark:text-blue-400 text-xs whitespace-nowrap">
                    <span className="flex items-center gap-1.5">
                      {finding.cve_id}
                      {finding.is_kev === 1 && (
                        <span className="text-xs font-bold bg-red-600 text-white px-1.5 py-0.5 rounded leading-none">
                          KEV
                        </span>
                      )}
                      {finding.ssvc_exploitation === "active" && (
                        <span className="text-xs font-bold bg-red-600 text-white px-1.5 py-0.5 rounded leading-none">
                          ACTIVE
                        </span>
                      )}
                      {finding.ssvc_exploitation === "poc" && (
                        <span className="text-xs font-bold bg-orange-500 text-white px-1.5 py-0.5 rounded leading-none">
                          PoC
                        </span>
                      )}
                      {finding.cvelist_state === "REJECTED" && (
                        <span className="text-xs font-bold bg-gray-500 text-white px-1.5 py-0.5 rounded leading-none line-through">
                          REJECTED
                        </span>
                      )}
                      {finding.cvss_score === null && finding.cvelist_state === "PUBLISHED" && (
                        <span className="text-xs font-bold bg-yellow-500 text-white px-1.5 py-0.5 rounded leading-none">
                          NVD PENDING
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={finding.cvss_severity} />
                  </td>
                  <td className="px-4 py-3 text-right text-gray-700 dark:text-gray-300 font-medium">
                    {finding.cvss_score !== null ? finding.cvss_score.toFixed(1) : "—"}
                  </td>
                  <td className="px-4 py-3 text-gray-500 dark:text-gray-400 whitespace-nowrap text-xs">
                    {finding.published_at
                      ? format(new Date(finding.published_at), "MMM d, yyyy")
                      : "—"}
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400 max-w-xs">
                    <p className="truncate">
                      {finding.description ?? finding.cvelist_cna_description ?? "—"}
                    </p>
                  </td>
                  <td className="px-4 py-3 text-gray-400 dark:text-gray-500 text-xs whitespace-nowrap">
                    {formatDistanceToNow(new Date(finding.found_at), { addSuffix: true })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          {pagination && pagination.pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100 dark:border-gray-700">
              <p className="text-xs text-gray-400 dark:text-gray-500">
                {pagination.total} total · page {pagination.page} of {pagination.pages}
              </p>
              <div className="flex gap-2">
                <button
                  disabled={page === 1}
                  onClick={() => setPage((p) => p - 1)}
                  className="text-xs px-3 py-1 border border-gray-200 dark:border-gray-700 rounded-lg disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800 dark:text-gray-300"
                >
                  Prev
                </button>
                <button
                  disabled={page === pagination.pages}
                  onClick={() => setPage((p) => p + 1)}
                  className="text-xs px-3 py-1 border border-gray-200 dark:border-gray-700 rounded-lg disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800 dark:text-gray-300"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {selectedCveId && (
        <CveDetailModal
          cveId={selectedCveId}
          onClose={() => setSelectedCveId(null)}
        />
      )}
    </div>
  );
}

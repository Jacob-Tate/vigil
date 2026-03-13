import { useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { PaginatedNvdCves } from "../types";
import { searchNvdCves } from "../api/client";
import CveDetailModal from "../components/CveDetailModal";
import { format } from "date-fns";

type Severity = "" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

function SeverityBadge({ severity }: { severity: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400",
    HIGH: "bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400",
    MEDIUM: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400",
    LOW: "bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400",
    NONE: "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400",
  };
  if (!severity) return <span className="text-gray-400 dark:text-gray-500 text-xs">—</span>;
  const cls = map[severity.toUpperCase()] ?? "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400";
  return (
    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${cls}`}>
      {severity}
    </span>
  );
}

export default function CveBrowser() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState<Severity>("");
  const [minScore, setMinScore] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const [results, setResults] = useState<PaginatedNvdCves | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const [searched, setSearched] = useState(false);

  const doSearch = useCallback(
    async (p = 1) => {
      setLoading(true);
      setError(null);
      try {
        const data = await searchNvdCves({
          q: q || undefined,
          severity: severity || undefined,
          minScore: minScore ? parseFloat(minScore) : undefined,
          from: from || undefined,
          to: to || undefined,
          page: p,
          limit: 50,
        });
        setResults(data);
        setPage(p);
        setSearched(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Search failed");
      } finally {
        setLoading(false);
      }
    },
    [q, severity, minScore, from, to]
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void doSearch(1);
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <Link to="/cve" className="text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300">
          ← CVE Monitor
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">CVE Browser</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
            Search the local NVD mirror
          </p>
        </div>
      </div>

      {/* Search form */}
      <form
        onSubmit={handleSubmit}
        className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl p-4 mb-6 space-y-3"
      >
        <div className="flex gap-3">
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by CVE ID or keyword (e.g. nginx, buffer overflow)"
            className="flex-1 border border-gray-200 dark:border-gray-600 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-blue-600 text-white px-5 py-2 rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? "Searching…" : "Search"}
          </button>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-3 items-end">
          <div>
            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Severity</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity)}
              className="border border-gray-200 dark:border-gray-600 rounded-lg px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
            >
              <option value="">Any</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="NONE">None</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Min CVSS</label>
            <input
              type="number"
              min={0}
              max={10}
              step={0.1}
              value={minScore}
              onChange={(e) => setMinScore(e.target.value)}
              placeholder="0–10"
              className="w-20 border border-gray-200 dark:border-gray-600 rounded-lg px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">Published from</label>
            <input
              type="date"
              value={from}
              onChange={(e) => setFrom(e.target.value)}
              className="border border-gray-200 dark:border-gray-600 rounded-lg px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-500 dark:text-gray-400 mb-1">To</label>
            <input
              type="date"
              value={to}
              onChange={(e) => setTo(e.target.value)}
              className="border border-gray-200 dark:border-gray-600 rounded-lg px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>
          {(q || severity || minScore || from || to) && (
            <button
              type="button"
              onClick={() => {
                setQ(""); setSeverity(""); setMinScore("");
                setFrom(""); setTo("");
                setResults(null); setSearched(false);
              }}
              className="text-sm text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300"
            >
              Clear
            </button>
          )}
        </div>
      </form>

      {/* Error */}
      {error && (
        <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-xl p-4 mb-4">{error}</div>
      )}

      {/* No data warning */}
      {!searched && !loading && (
        <div className="text-center py-12 text-gray-400 dark:text-gray-500">
          <svg
            className="w-10 h-10 mx-auto mb-3 text-gray-200 dark:text-gray-700"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <p className="text-sm font-medium">Enter a search to browse CVEs</p>
          <p className="text-xs mt-1">
            The local NVD mirror must be synced first.{" "}
            <Link to="/cve" className="text-blue-500 hover:underline">
              Go to CVE Monitor →
            </Link>
          </p>
        </div>
      )}

      {searched && !loading && (results?.data.length ?? 0) === 0 && (
        <div className="text-center py-8 text-gray-400 dark:text-gray-500 text-sm">
          No CVEs found matching your criteria.
        </div>
      )}

      {/* Results table */}
      {results && results.data.length > 0 && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden">
          <div className="px-4 py-2.5 border-b border-gray-100 dark:border-gray-700 text-xs text-gray-500 dark:text-gray-400">
            {results.pagination.total.toLocaleString()} results · page{" "}
            {results.pagination.page} of {results.pagination.pages}
          </div>
          <table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-800 border-b border-gray-100 dark:border-gray-700">
              <tr>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400">CVE ID</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400">Severity</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400">CVSS</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400">Published</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-gray-500 dark:text-gray-400 max-w-sm">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50 dark:divide-gray-700">
              {results.data.map((cve) => (
                <tr
                  key={cve.cve_id}
                  className="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                  onClick={() => setSelectedCveId(cve.cve_id)}
                >
                  <td className="px-4 py-3 font-mono text-blue-600 dark:text-blue-400 text-xs whitespace-nowrap">
                    {cve.cve_id}
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity={cve.cvss_severity} />
                  </td>
                  <td className="px-4 py-3 text-right text-gray-700 dark:text-gray-300 font-medium text-xs">
                    {cve.cvss_score !== null ? cve.cvss_score.toFixed(1) : "—"}
                  </td>
                  <td className="px-4 py-3 text-gray-500 dark:text-gray-400 whitespace-nowrap text-xs">
                    {cve.published_at
                      ? format(new Date(cve.published_at), "MMM d, yyyy")
                      : "—"}
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400 max-w-sm">
                    <p className="truncate text-xs">{cve.description ?? "—"}</p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          {results.pagination.pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100 dark:border-gray-700">
              <p className="text-xs text-gray-400 dark:text-gray-500">
                Showing {(page - 1) * 50 + 1}–
                {Math.min(page * 50, results.pagination.total)} of{" "}
                {results.pagination.total.toLocaleString()}
              </p>
              <div className="flex gap-2">
                <button
                  disabled={page === 1}
                  onClick={() => void doSearch(page - 1)}
                  className="text-xs px-3 py-1 border border-gray-200 dark:border-gray-700 rounded-lg disabled:opacity-40 hover:bg-gray-50 dark:hover:bg-gray-800 dark:text-gray-300"
                >
                  Prev
                </button>
                <button
                  disabled={page === results.pagination.pages}
                  onClick={() => void doSearch(page + 1)}
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

import { useState, useEffect } from "react";
import { NvdCveDetail, NvdCveRef } from "../types";
import { getNvdCve } from "../api/client";
import { format } from "date-fns";

function KevBanner({ kev }: { kev: NonNullable<NvdCveDetail["kev"]> }) {
  const isRansomware = kev.known_ransomware_campaign_use === "Known";
  return (
    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3 space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-bold text-red-700 dark:text-red-400 uppercase tracking-wide">
          ⚠ CISA Known Exploited Vulnerability
        </span>
        {isRansomware && (
          <span className="text-xs font-semibold bg-red-200 dark:bg-red-800 text-red-800 dark:text-red-200 px-1.5 py-0.5 rounded">
            Ransomware
          </span>
        )}
      </div>
      {kev.vulnerability_name && (
        <p className="text-xs font-medium text-red-800 dark:text-red-300">{kev.vulnerability_name}</p>
      )}
      <div className="flex gap-4 text-xs text-red-700 dark:text-red-400">
        <span>Added to KEV: <span className="font-medium">{format(new Date(kev.date_added), "MMM d, yyyy")}</span></span>
        {kev.due_date && (
          <span>Due: <span className="font-medium">{format(new Date(kev.due_date), "MMM d, yyyy")}</span></span>
        )}
      </div>
      {kev.required_action && (
        <p className="text-xs text-red-700 dark:text-red-400">
          <span className="font-semibold">Required action:</span> {kev.required_action}
        </p>
      )}
    </div>
  );
}

interface Props {
  cveId: string;
  onClose: () => void;
}

function SeverityBadge({ severity, score }: { severity: string | null; score: number | null }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800",
    HIGH: "bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-800",
    MEDIUM: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800",
    LOW: "bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-800",
    NONE: "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 border-gray-200 dark:border-gray-600",
  };
  const cls = map[severity?.toUpperCase() ?? ""] ?? "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 border-gray-200 dark:border-gray-600";
  return (
    <span className={`text-sm font-semibold px-2 py-1 rounded border ${cls}`}>
      {severity ?? "N/A"} {score !== null ? `(${score.toFixed(1)})` : ""}
    </span>
  );
}

export default function CveDetailModal({ cveId, onClose }: Props) {
  const [detail, setDetail] = useState<NvdCveDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getNvdCve(cveId)
      .then((d) => {
        if (!cancelled) { setDetail(d); setLoading(false); }
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load CVE");
          setLoading(false);
        }
      });
    return () => { cancelled = true; };
  }, [cveId]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-2xl w-full max-w-2xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100 dark:border-gray-700 shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="text-base font-semibold text-gray-900 dark:text-white font-mono">{cveId}</h2>
            {detail && (
              <SeverityBadge severity={detail.cvss_severity} score={detail.cvss_score} />
            )}
          </div>
          <div className="flex items-center gap-2">
            {detail?.nvd_url ? (
              <a
                href={detail.nvd_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
              >
                NVD ↗
              </a>
            ) : (
              <a
                href={`https://www.cve.org/CVERecord?id=${cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
              >
                CVE.org ↗
              </a>
            )}
            <button
              onClick={onClose}
              className="text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 text-lg leading-none"
            >
              ×
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto px-6 py-4 space-y-4">
          {loading && (
            <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-8">Loading…</p>
          )}
          {error && (
            <p className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-lg p-3">{error}</p>
          )}
          {detail && (
            <>
              {/* Dates */}
              <div className="flex gap-4 text-xs text-gray-500 dark:text-gray-400">
                {detail.published_at && (
                  <span>
                    Published:{" "}
                    <span className="text-gray-700 dark:text-gray-300">
                      {format(new Date(detail.published_at), "MMM d, yyyy")}
                    </span>
                  </span>
                )}
                {detail.last_modified_at && (
                  <span>
                    Updated:{" "}
                    <span className="text-gray-700 dark:text-gray-300">
                      {format(new Date(detail.last_modified_at), "MMM d, yyyy")}
                    </span>
                  </span>
                )}
              </div>

              {/* KEV banner */}
              {detail.kev && <KevBanner kev={detail.kev} />}

              {/* SSVC section */}
              {detail.ssvc && (
                <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3 space-y-2">
                  <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                    CISA SSVC
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {detail.ssvc.exploitation && (
                      <span className={`text-xs font-semibold px-2 py-1 rounded border ${
                        detail.ssvc.exploitation === "active"
                          ? "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800"
                          : detail.ssvc.exploitation === "poc"
                          ? "bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-800"
                          : "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 border-gray-200 dark:border-gray-600"
                      }`}>
                        Exploitation: {detail.ssvc.exploitation}
                      </span>
                    )}
                    {detail.ssvc.automatable && (
                      <span className={`text-xs font-semibold px-2 py-1 rounded border ${
                        detail.ssvc.automatable === "yes"
                          ? "bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-800"
                          : "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800"
                      }`}>
                        Automatable: {detail.ssvc.automatable}
                      </span>
                    )}
                    {detail.ssvc.technical_impact && (
                      <span className={`text-xs font-semibold px-2 py-1 rounded border ${
                        detail.ssvc.technical_impact === "total"
                          ? "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800"
                          : "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800"
                      }`}>
                        Technical Impact: {detail.ssvc.technical_impact}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* cvelistV5 state */}
              {detail.cvelist && (
                <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3 space-y-2">
                  <div className="flex items-center gap-2">
                    <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide">
                      CVE Program (cvelistV5)
                    </p>
                    {detail.cvelist.state === "REJECTED" ? (
                      <span className="text-xs font-bold bg-gray-500 text-white px-1.5 py-0.5 rounded leading-none line-through">
                        REJECTED
                      </span>
                    ) : detail.cvelist.state === "PUBLISHED" ? (
                      <span className="text-xs font-bold bg-green-600 text-white px-1.5 py-0.5 rounded leading-none">
                        PUBLISHED
                      </span>
                    ) : (
                      <span className="text-xs font-bold bg-yellow-500 text-white px-1.5 py-0.5 rounded leading-none">
                        {detail.cvelist.state}
                      </span>
                    )}
                  </div>
                  {detail.description === null && detail.cvelist.cna_description && (
                    <div>
                      <p className="text-xs text-gray-400 dark:text-gray-500 mb-0.5">CNA Description — NVD pending</p>
                      <p className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed">
                        {detail.cvelist.cna_description}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Description */}
              <div>
                <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1.5">
                  Description
                </h3>
                <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                  {detail.description ?? detail.cvelist?.cna_description ?? "No description available."}
                </p>
              </div>

              {/* Affected CPEs */}
              {detail.cpe_entries.length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1.5">
                    Affected Configurations ({detail.cpe_entries.length})
                  </h3>
                  <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 max-h-48 overflow-y-auto space-y-1">
                    {detail.cpe_entries.map((entry, i) => {
                      const { version_start_including: vsi, version_start_excluding: vse,
                              version_end_including: vei, version_end_excluding: vee } = entry;
                      const parts: string[] = [];
                      if (vsi) parts.push(`≥ ${vsi}`);
                      if (vse) parts.push(`> ${vse}`);
                      if (vei) parts.push(`≤ ${vei}`);
                      if (vee) parts.push(`< ${vee}`);
                      return (
                        <div key={i} className="flex items-baseline gap-2 flex-wrap">
                          <span className="text-xs font-mono text-gray-600 dark:text-gray-400 break-all">{entry.cpe_string}</span>
                          {parts.length > 0 && (
                            <span className="text-xs text-gray-400 dark:text-gray-500 whitespace-nowrap shrink-0">
                              ({parts.join(", ")})
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* References */}
              {(detail.references?.length ?? 0) > 0 && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1.5">
                    References ({detail.references!.length})
                  </h3>
                  <div className="space-y-1.5">
                    {detail.references!.map((ref: NvdCveRef, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-xs">
                        <a
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 dark:text-blue-400 hover:underline break-all min-w-0 flex-1"
                        >
                          {ref.url}
                        </a>
                        {ref.tags && ref.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1 shrink-0">
                            {ref.tags.map((tag, ti) => (
                              <span
                                key={ti}
                                className="bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 px-1.5 py-0.5 rounded text-xs whitespace-nowrap"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

import { useState, useEffect } from "react";
import { NvdCveDetail, NvdCveRef } from "../types";
import { getNvdCve } from "../api/client";
import { format } from "date-fns";

interface Props {
  cveId: string;
  onClose: () => void;
}

function SeverityBadge({ severity, score }: { severity: string | null; score: number | null }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-700 border-red-200",
    HIGH: "bg-orange-100 text-orange-700 border-orange-200",
    MEDIUM: "bg-yellow-100 text-yellow-700 border-yellow-200",
    LOW: "bg-blue-100 text-blue-700 border-blue-200",
    NONE: "bg-gray-100 text-gray-500 border-gray-200",
  };
  const cls = map[severity?.toUpperCase() ?? ""] ?? "bg-gray-100 text-gray-500 border-gray-200";
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
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100 shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="text-base font-semibold text-gray-900 font-mono">{cveId}</h2>
            {detail && (
              <SeverityBadge severity={detail.cvss_severity} score={detail.cvss_score} />
            )}
          </div>
          <div className="flex items-center gap-2">
            {detail?.nvd_url && (
              <a
                href={detail.nvd_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-600 hover:underline"
              >
                NVD ↗
              </a>
            )}
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 text-lg leading-none"
            >
              ×
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="overflow-y-auto px-6 py-4 space-y-4">
          {loading && (
            <p className="text-sm text-gray-400 text-center py-8">Loading…</p>
          )}
          {error && (
            <p className="text-sm text-red-600 bg-red-50 rounded-lg p-3">{error}</p>
          )}
          {detail && (
            <>
              {/* Dates */}
              <div className="flex gap-4 text-xs text-gray-500">
                {detail.published_at && (
                  <span>
                    Published:{" "}
                    <span className="text-gray-700">
                      {format(new Date(detail.published_at), "MMM d, yyyy")}
                    </span>
                  </span>
                )}
                {detail.last_modified_at && (
                  <span>
                    Updated:{" "}
                    <span className="text-gray-700">
                      {format(new Date(detail.last_modified_at), "MMM d, yyyy")}
                    </span>
                  </span>
                )}
              </div>

              {/* Description */}
              <div>
                <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
                  Description
                </h3>
                <p className="text-sm text-gray-700 leading-relaxed">
                  {detail.description ?? "No description available."}
                </p>
              </div>

              {/* Affected CPEs */}
              {detail.cpe_entries.length > 0 && (
                <div>
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
                    Affected Configurations ({detail.cpe_entries.length})
                  </h3>
                  <div className="bg-gray-50 rounded-lg p-3 max-h-48 overflow-y-auto space-y-1">
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
                          <span className="text-xs font-mono text-gray-600 break-all">{entry.cpe_string}</span>
                          {parts.length > 0 && (
                            <span className="text-xs text-gray-400 whitespace-nowrap shrink-0">
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
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
                    References ({detail.references!.length})
                  </h3>
                  <div className="space-y-1.5">
                    {detail.references!.map((ref: NvdCveRef, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-xs">
                        <a
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:underline break-all min-w-0 flex-1"
                        >
                          {ref.url}
                        </a>
                        {ref.tags && ref.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1 shrink-0">
                            {ref.tags.map((tag, ti) => (
                              <span
                                key={ti}
                                className="bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded text-xs whitespace-nowrap"
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

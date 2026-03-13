import { Link } from "react-router-dom";
import { CveTargetWithStats } from "../types";
import { formatDistanceToNow } from "date-fns";

interface Props {
  target: CveTargetWithStats;
  onCheck?: (id: number) => void;
  onEdit?: (target: CveTargetWithStats) => void;
  onDelete?: (id: number) => void;
  checking: boolean;
}

function SeverityBadge({ severity }: { severity: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400",
    HIGH: "bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400",
    MEDIUM: "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400",
    LOW: "bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400",
    NONE: "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400",
  };
  const cls = map[severity?.toUpperCase() ?? ""] ?? "bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400";
  return (
    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${cls}`}>
      {severity ?? "—"}
    </span>
  );
}

export default function CveTargetCard({
  target,
  onCheck,
  onEdit,
  onDelete,
  checking,
}: Props) {
  const topSeverity = target.top_cvss_severity ?? null;
  const topScore = target.top_cvss_score ?? null;

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl p-4 flex flex-col gap-3 hover:shadow-sm transition-shadow">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <Link
            to={`/cve/${target.id}`}
            className="text-sm font-semibold text-gray-900 dark:text-white hover:text-blue-600 truncate block"
          >
            {target.name}
          </Link>
          <p className="text-xs text-gray-400 dark:text-gray-500 font-mono mt-0.5">
            {target.vendor ? `${target.vendor}:` : ""}
            {target.product}
            {target.version ? `:${target.version}` : ""}
          </p>
        </div>
        {target.findings_count > 0 && (
          <SeverityBadge severity={topSeverity} />
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-2">
          <p className="text-lg font-bold text-gray-900 dark:text-white">{target.findings_count}</p>
          <p className="text-xs text-gray-400 dark:text-gray-500">CVEs found</p>
        </div>
        <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-2">
          <p className="text-lg font-bold text-gray-900 dark:text-white">
            {topScore !== null ? topScore.toFixed(1) : "—"}
          </p>
          <p className="text-xs text-gray-400 dark:text-gray-500">Top CVSS</p>
        </div>
        <div className={`rounded-lg p-2 ${target.kev_count > 0 ? "bg-red-50 dark:bg-red-900/20" : "bg-gray-50 dark:bg-gray-800"}`}>
          <p className={`text-lg font-bold ${target.kev_count > 0 ? "text-red-600 dark:text-red-400" : "text-gray-900 dark:text-white"}`}>
            {target.kev_count}
          </p>
          <p className={`text-xs ${target.kev_count > 0 ? "text-red-400 dark:text-red-500" : "text-gray-400 dark:text-gray-500"}`}>
            KEVs
          </p>
        </div>
      </div>

      {/* Last checked */}
      <p className="text-xs text-gray-400 dark:text-gray-500">
        {target.last_checked_at
          ? `Checked ${formatDistanceToNow(new Date(target.last_checked_at), { addSuffix: true })}`
          : "Not yet checked"}
      </p>

      {/* Actions */}
      <div className="flex gap-1.5 mt-auto">
        <Link
          to={`/cve/${target.id}`}
          className="flex-1 text-center text-xs border border-gray-200 dark:border-gray-700 rounded-lg py-1.5 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
        >
          View
        </Link>
        {onCheck && (
          <button
            onClick={() => onCheck(target.id)}
            disabled={checking}
            className="flex-1 text-xs border border-gray-200 dark:border-gray-700 rounded-lg py-1.5 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors disabled:opacity-50"
          >
            {checking ? "…" : "Check"}
          </button>
        )}
        {onEdit && (
          <button
            onClick={() => onEdit(target)}
            className="text-xs border border-gray-200 dark:border-gray-700 rounded-lg px-2.5 py-1.5 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
          >
            Edit
          </button>
        )}
        {onDelete && (
          <button
            onClick={() => onDelete(target.id)}
            className="text-xs border border-red-100 dark:border-red-900/40 rounded-lg px-2.5 py-1.5 text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
          >
            Del
          </button>
        )}
      </div>
    </div>
  );
}

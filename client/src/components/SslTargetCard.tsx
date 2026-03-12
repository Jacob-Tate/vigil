import { useNavigate } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { SslTarget } from "../types";

interface Props {
  target: SslTarget;
  onCheck: (id: number) => void;
  onEdit: (target: SslTarget) => void;
  onDelete: (id: number) => void;
  checking: boolean;
}

type SslStatus = "valid" | "expiring" | "expired" | "error" | "pending";

function getStatus(target: SslTarget): SslStatus {
  const check = target.last_check;
  if (!check) return "pending";
  if (check.error) return "error";
  if (check.days_remaining === null) return "pending";
  if (check.days_remaining < 0) return "expired";
  if (check.days_remaining <= target.expiry_threshold_hours / 24) return "expiring";
  return "valid";
}

const STATUS_STYLES: Record<SslStatus, { dot: string; pill: string; label: string }> = {
  valid:   { dot: "bg-green-500", pill: "bg-green-100 text-green-700",  label: "Valid" },
  expiring:{ dot: "bg-amber-500", pill: "bg-amber-100 text-amber-700",  label: "Expiring" },
  expired: { dot: "bg-red-500",   pill: "bg-red-100 text-red-700",      label: "Expired" },
  error:   { dot: "bg-red-500",   pill: "bg-red-100 text-red-700",      label: "Error" },
  pending: { dot: "bg-gray-300",  pill: "bg-gray-100 text-gray-500",    label: "Pending" },
};

const BORDER_COLOR: Record<SslStatus, string> = {
  valid:   "border-l-green-400",
  expiring:"border-l-amber-400",
  expired: "border-l-red-400",
  error:   "border-l-red-400",
  pending: "border-l-gray-200",
};

export default function SslTargetCard({ target, onCheck, onEdit, onDelete, checking }: Props) {
  const navigate = useNavigate();
  const status = getStatus(target);
  const { dot, pill, label } = STATUS_STYLES[status];
  const borderColor = BORDER_COLOR[status];

  const check = target.last_check;

  return (
    <div
      className={`bg-white rounded-xl border border-l-4 ${borderColor} border-gray-200 shadow-sm hover:shadow-md transition-shadow cursor-pointer`}
      onClick={() => navigate(`/ssl/${target.id}`)}
    >
      <div className="p-4">
        {/* Header */}
        <div className="flex items-start justify-between gap-2 mb-3">
          <div className="min-w-0">
            <h3 className="font-semibold text-gray-900 truncate">{target.name}</h3>
            <p className="text-sm text-gray-500 truncate font-mono">
              {target.host}:{target.port}
            </p>
          </div>
          <span className={`text-xs font-semibold px-2 py-0.5 rounded-full shrink-0 ${pill} flex items-center gap-1`}>
            <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
            {label}
          </span>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-2 text-sm mb-3">
          <div>
            <p className="text-xs text-gray-400">Days Remaining</p>
            <p className={`font-semibold ${
              check?.days_remaining !== undefined && check?.days_remaining !== null
                ? check.days_remaining < 0
                  ? "text-red-600"
                  : check.days_remaining <= 7
                  ? "text-red-600"
                  : check.days_remaining <= 30
                  ? "text-amber-600"
                  : "text-green-600"
                : "text-gray-400"
            }`}>
              {check?.days_remaining !== undefined && check?.days_remaining !== null
                ? `${check.days_remaining}d`
                : "—"}
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-400">TLS Version</p>
            <p className="font-medium text-gray-700">{check?.tls_version ?? "—"}</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">Issuer</p>
            <p className="text-gray-700 truncate">{check?.issuer_cn ?? "—"}</p>
          </div>
          <div>
            <p className="text-xs text-gray-400">Last Check</p>
            <p className="text-gray-500 text-xs">
              {target.last_checked_at
                ? formatDistanceToNow(new Date(target.last_checked_at), { addSuffix: true })
                : "Never"}
            </p>
          </div>
        </div>

        {check?.error && (
          <p className="text-xs text-red-600 bg-red-50 rounded p-2 mb-3 truncate">
            {check.error}
          </p>
        )}
      </div>

      {/* Actions */}
      <div
        className="border-t border-gray-100 px-4 py-2 flex gap-2"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          onClick={() => onCheck(target.id)}
          disabled={checking}
          className="text-xs text-blue-600 hover:text-blue-800 disabled:opacity-40 font-medium transition-colors"
        >
          {checking ? "Checking…" : "Check now"}
        </button>
        <span className="text-gray-200">|</span>
        <button
          onClick={() => onEdit(target)}
          className="text-xs text-gray-500 hover:text-gray-800 font-medium transition-colors"
        >
          Edit
        </button>
        <span className="text-gray-200">|</span>
        <button
          onClick={() => onDelete(target.id)}
          className="text-xs text-red-400 hover:text-red-600 font-medium transition-colors"
        >
          Delete
        </button>
      </div>
    </div>
  );
}

import { useState } from "react";
import { Link } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { Server } from "../types";
import StatusBadge from "./StatusBadge";
import { parseApiDate } from "../utils/date";

interface Props {
  server: Server;
  onEdit?: (server: Server) => void;
  onDelete?: (server: Server) => void;
  onCheck?: (server: Server) => void;
}

export default function ServerCard({ server, onEdit, onDelete, onCheck }: Props) {
  const check = server.last_check;
  const isUp = check ? check.is_up === 1 : null;
  const isDegraded =
    isUp === true &&
    check !== null &&
    check.response_time_ms !== null &&
    check.response_time_ms > server.response_time_threshold_ms;

  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewKey, setPreviewKey] = useState(0);
  const [imgLoaded, setImgLoaded] = useState(false);
  const [imgError, setImgError] = useState<string | null>(null);

  function openPreview() {
    setImgLoaded(false);
    setImgError(null);
    setPreviewOpen(true);
  }

  function refreshPreview() {
    setImgLoaded(false);
    setImgError(null);
    setPreviewKey((k) => k + 1);
  }

  async function handleImgError() {
    try {
      const res = await fetch(`/api/servers/${server.id}/screenshot?force=0`);
      if (!res.ok) {
        const body = await res.json() as { error?: string };
        setImgError(body.error ?? "Unknown error");
      } else {
        setImgError("Unknown error");
      }
    } catch {
      setImgError("Could not reach server");
    }
  }

  return (
    <>
      <div className={`bg-white rounded-xl border shadow-sm p-4 flex flex-col gap-3 transition-all ${
        isUp === false ? "border-red-200" : isDegraded ? "border-yellow-200" : "border-gray-200"
      }`}>
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <Link
              to={`/http/servers/${server.id}`}
              className="font-semibold text-gray-900 hover:text-blue-600 truncate block"
            >
              {server.name}
            </Link>
            <a
              href={server.url}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-gray-400 hover:text-blue-500 truncate block"
            >
              {server.url}
            </a>
          </div>
          <StatusBadge isUp={isUp} isDegraded={isDegraded} />
        </div>

        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <p className="text-gray-400 text-xs">Response time</p>
            <p className="font-medium text-gray-700">
              {check?.response_time_ms != null ? `${check.response_time_ms}ms` : "—"}
            </p>
          </div>
          <div>
            <p className="text-gray-400 text-xs">Status code</p>
            <p className="font-medium text-gray-700">{check?.status_code ?? "—"}</p>
          </div>
          <div>
            <p className="text-gray-400 text-xs">Interval</p>
            <p className="font-medium text-gray-700">{server.interval_seconds}s</p>
          </div>
          <div>
            <p className="text-gray-400 text-xs">Last checked</p>
            <p className="font-medium text-gray-700 text-xs">
              {check
                ? formatDistanceToNow(parseApiDate(check.checked_at), { addSuffix: true })
                : "Never"}
            </p>
          </div>
        </div>

        <div className="flex gap-2 pt-1 border-t border-gray-100">
          {onCheck && (
            <button
              onClick={() => onCheck(server)}
              className="text-xs px-2 py-1 rounded bg-blue-50 text-blue-600 hover:bg-blue-100 transition-colors"
            >
              Check now
            </button>
          )}
          <button
            onClick={openPreview}
            className="text-xs px-2 py-1 rounded bg-purple-50 text-purple-600 hover:bg-purple-100 transition-colors"
          >
            Preview
          </button>
          {onEdit && (
            <button
              onClick={() => onEdit(server)}
              className="text-xs px-2 py-1 rounded bg-gray-50 text-gray-600 hover:bg-gray-100 transition-colors"
            >
              Edit
            </button>
          )}
          {onDelete && (
            <button
              onClick={() => onDelete(server)}
              className="text-xs px-2 py-1 rounded bg-red-50 text-red-500 hover:bg-red-100 transition-colors ml-auto"
            >
              Delete
            </button>
          )}
        </div>
      </div>

      {previewOpen && (
        <div
          className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4"
          onClick={() => setPreviewOpen(false)}
        >
          <div
            className="bg-white rounded-xl shadow-2xl w-full max-w-4xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
              <div className="min-w-0">
                <p className="font-semibold text-gray-900 truncate">{server.name}</p>
                <a
                  href={server.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-gray-400 hover:text-blue-500 truncate block"
                >
                  {server.url}
                </a>
              </div>
              <div className="flex items-center gap-2 ml-4 shrink-0">
                <button
                  onClick={refreshPreview}
                  className="text-xs px-3 py-1 rounded bg-blue-50 text-blue-600 hover:bg-blue-100 transition-colors"
                >
                  Refresh
                </button>
                <button
                  onClick={() => setPreviewOpen(false)}
                  className="text-gray-400 hover:text-gray-600 text-lg leading-none px-1"
                >
                  ✕
                </button>
              </div>
            </div>

            <div className="relative bg-gray-50 min-h-48 flex items-center justify-center">
              {!imgLoaded && !imgError && (
                <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-gray-500">
                  <svg
                    className="animate-spin h-6 w-6 text-purple-500"
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z" />
                  </svg>
                  <span className="text-sm">Capturing screenshot…</span>
                </div>
              )}
              {imgError && (
                <div className="flex flex-col items-center justify-center gap-2 text-red-500 p-8 text-center">
                  <span className="text-3xl">⚠</span>
                  <p className="text-sm font-medium">Failed to capture preview</p>
                  <p className="text-xs text-gray-500">{imgError}</p>
                </div>
              )}
              {!imgError && (
                <img
                  key={previewKey}
                  src={`/api/servers/${server.id}/screenshot?force=${previewKey > 0 ? "1" : "0"}`}
                  alt={`Preview of ${server.name}`}
                  className={`w-full block ${imgLoaded ? "" : "invisible absolute"}`}
                  onLoad={() => setImgLoaded(true)}
                  onError={() => { void handleImgError(); }}
                />
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

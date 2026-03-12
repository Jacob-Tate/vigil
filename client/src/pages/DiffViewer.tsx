import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { format } from "date-fns";
import { getDiff } from "../api/client";
import { parseApiDate } from "../utils/date";
import { ContentDiff } from "../types";
import DiffPanel from "../components/DiffPanel";

export default function DiffViewer() {
  const { id, diffId } = useParams<{ id: string; diffId: string }>();
  const serverId = parseInt(id ?? "0", 10);
  const diffIdNum = parseInt(diffId ?? "0", 10);

  const [diff, setDiff] = useState<ContentDiff | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDiff(diffIdNum)
      .then(setDiff)
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "Failed to load diff");
      })
      .finally(() => setLoading(false));
  }, [diffIdNum]);

  return (
    <div className="max-w-6xl mx-auto px-4 py-6">
      <div className="mb-6">
        <Link
          to={`/servers/${serverId}`}
          className="text-sm text-gray-400 hover:text-blue-600 mb-2 inline-block"
        >
          ← Server detail
        </Link>
        <h1 className="text-2xl font-bold text-gray-900">Content Diff</h1>
        {diff && (
          <p className="text-sm text-gray-400 mt-1">
            Detected {format(parseApiDate(diff.detected_at), "PPpp")}
          </p>
        )}
      </div>

      {loading && <p className="text-center py-16 text-gray-400">Loading diff…</p>}
      {error && <p className="text-center py-16 text-red-400">{error}</p>}

      {diff && (
        <>
          <div className="flex gap-4 mb-4 text-xs text-gray-500 font-mono bg-gray-50 rounded-lg p-3 border">
            <div>
              <span className="text-gray-400">Old hash: </span>
              <span className="text-gray-700">{diff.old_hash?.slice(0, 16)}…</span>
            </div>
            <div>
              <span className="text-gray-400">New hash: </span>
              <span className="text-gray-700">{diff.new_hash?.slice(0, 16)}…</span>
            </div>
          </div>
          <DiffPanel diffContent={diff.diff_content ?? ""} />
        </>
      )}
    </div>
  );
}

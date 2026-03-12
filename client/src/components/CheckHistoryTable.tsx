import { Link } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { Check } from "../types";
import { parseApiDate } from "../utils/date";
import StatusBadge from "./StatusBadge";

interface Props {
  checks: Check[];
  serverId: number;
  responseThresholdMs: number;
}

export default function CheckHistoryTable({ checks, serverId, responseThresholdMs }: Props) {
  if (checks.length === 0) {
    return <p className="text-gray-400 text-sm text-center py-8">No checks recorded yet.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-gray-400 border-b">
            <th className="pb-2 font-medium">Time</th>
            <th className="pb-2 font-medium">Status</th>
            <th className="pb-2 font-medium">HTTP</th>
            <th className="pb-2 font-medium">Response time</th>
            <th className="pb-2 font-medium">Content</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {checks.map((check) => {
            const isUp = check.is_up === 1;
            const isDegraded =
              isUp &&
              check.response_time_ms !== null &&
              check.response_time_ms > responseThresholdMs;
            return (
              <tr key={check.id} className="hover:bg-gray-50 transition-colors">
                <td className="py-2 text-gray-500">
                  {formatDistanceToNow(parseApiDate(check.checked_at), { addSuffix: true })}
                </td>
                <td className="py-2">
                  <StatusBadge isUp={isUp} isDegraded={isDegraded} small />
                </td>
                <td className="py-2 text-gray-600">{check.status_code ?? "—"}</td>
                <td className="py-2 text-gray-600">
                  {check.response_time_ms != null ? (
                    <span className={check.response_time_ms > responseThresholdMs ? "text-yellow-600 font-medium" : ""}>
                      {check.response_time_ms}ms
                    </span>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="py-2">
                  {check.content_changed === 1 && check.diff_id !== null ? (
                    <Link
                      to={`/http/servers/${serverId}/diff/${check.diff_id}`}
                      className="text-blue-600 hover:underline text-xs"
                    >
                      View diff
                    </Link>
                  ) : (
                    <span className="text-gray-300 text-xs">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

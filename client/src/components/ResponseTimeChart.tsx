import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ReferenceLine,
} from "recharts";
import { format } from "date-fns";
import { Check } from "../types";
import { parseApiDate } from "../utils/date";

interface Props {
  checks: Check[];
  thresholdMs: number;
}

interface ChartPoint {
  time: string;
  ms: number | null;
  is_up: boolean;
}

export default function ResponseTimeChart({ checks, thresholdMs }: Props) {
  if (checks.length === 0) {
    return <p className="text-gray-400 text-sm text-center py-8">No data yet.</p>;
  }

  // Show last 50 checks, oldest first
  const data: ChartPoint[] = [...checks]
    .slice(0, 50)
    .reverse()
    .map((c) => ({
      time: format(parseApiDate(c.checked_at), "HH:mm"),
      ms: c.response_time_ms,
      is_up: c.is_up === 1,
    }));

  return (
    <ResponsiveContainer width="100%" height={140}>
      <AreaChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
        <defs>
          <linearGradient id="rtGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis
          dataKey="time"
          tick={{ fontSize: 10, fill: "#9ca3af" }}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          tick={{ fontSize: 10, fill: "#9ca3af" }}
          tickLine={false}
          axisLine={false}
          unit="ms"
        />
        <Tooltip
          contentStyle={{ fontSize: 12, borderRadius: 8, border: "1px solid #e5e7eb" }}
          formatter={(value: number) => [`${value}ms`, "Response time"]}
        />
        <ReferenceLine
          y={thresholdMs}
          stroke="#f59e0b"
          strokeDasharray="3 3"
          label={{ value: "Threshold", fontSize: 10, fill: "#f59e0b" }}
        />
        <Area
          type="monotone"
          dataKey="ms"
          stroke="#3b82f6"
          fill="url(#rtGrad)"
          strokeWidth={2}
          dot={false}
          connectNulls={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

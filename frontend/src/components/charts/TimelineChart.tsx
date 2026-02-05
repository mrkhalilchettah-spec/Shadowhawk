/**
 * ShadowHawk Platform Timeline Visualization
 */
import { cn } from "@/lib/utils";

type TimelineEvent = {
  label: string;
  timestamp: string;
  severity: "low" | "medium" | "high";
};

type TimelineChartProps = {
  events: TimelineEvent[];
  className?: string;
};

const severityStyles: Record<TimelineEvent["severity"], string> = {
  low: "bg-sky-500",
  medium: "bg-amber-500",
  high: "bg-rose-500"
};

export const TimelineChart = ({ events, className }: TimelineChartProps) => (
  <ol className={cn("space-y-4", className)} aria-label="Attack path timeline">
    {events.map((event) => (
      <li key={`${event.label}-${event.timestamp}`} className="flex items-start gap-4">
        <span className={cn("mt-1 h-3 w-3 rounded-full", severityStyles[event.severity])} aria-hidden="true" />
        <div>
          <p className="text-sm font-semibold text-slate-100">{event.label}</p>
          <p className="text-xs text-slate-400">{event.timestamp}</p>
        </div>
      </li>
    ))}
  </ol>
);

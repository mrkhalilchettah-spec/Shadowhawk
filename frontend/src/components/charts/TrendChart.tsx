/**
 * ShadowHawk Platform Trend Chart Placeholder
 */
import { cn } from "@/lib/utils";

type TrendChartProps = {
  data: number[];
  className?: string;
};

export const TrendChart = ({ data, className }: TrendChartProps) => {
  const maxValue = Math.max(...data, 1);

  return (
    <div className={cn("flex h-32 items-end gap-2", className)} role="img" aria-label="Risk trend chart">
      {data.map((value, index) => (
        <div
          key={`trend-bar-${index}`}
          className="flex-1 rounded-md bg-brand-600/70"
          style={{ height: `${Math.round((value / maxValue) * 100)}%` }}
        />
      ))}
    </div>
  );
};

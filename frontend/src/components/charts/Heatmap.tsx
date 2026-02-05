/**
 * ShadowHawk Platform Heatmap Placeholder
 */
import { cn } from "@/lib/utils";

type HeatmapProps = {
  matrix: number[][];
  className?: string;
};

export const Heatmap = ({ matrix, className }: HeatmapProps) => (
  <div className={cn("grid gap-2", className)} style={{ gridTemplateColumns: `repeat(${matrix[0]?.length ?? 1}, minmax(0, 1fr))` }}>
    {matrix.flatMap((row, rowIndex) =>
      row.map((value, colIndex) => (
        <div
          key={`heat-${rowIndex}-${colIndex}`}
          className="aspect-square rounded-md bg-brand-500/20"
          style={{ backgroundColor: `rgba(91, 140, 255, ${Math.min(0.85, value / 100)})` }}
          aria-hidden="true"
        />
      ))
    )}
  </div>
);

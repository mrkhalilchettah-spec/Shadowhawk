/**
 * ShadowHawk Platform Threat Topology Visualization
 */
import { cn } from "@/lib/utils";
import type { ThreatModelNode } from "@/types";

const riskTone: Record<string, string> = {
  Critical: "bg-rose-500/20 border-rose-500/50 text-rose-200",
  High: "bg-amber-500/20 border-amber-500/50 text-amber-200",
  Medium: "bg-sky-500/20 border-sky-500/50 text-sky-200",
  Low: "bg-emerald-500/20 border-emerald-500/50 text-emerald-200"
};

export const TopologyMap = ({ nodes, className }: { nodes: ThreatModelNode[]; className?: string }) => (
  <div className={cn("grid gap-4 sm:grid-cols-2", className)}>
    {nodes.map((node) => (
      <div
        key={node.id}
        className={cn(
          "rounded-lg border px-4 py-3 text-sm font-semibold",
          riskTone[node.risk] ?? "bg-slate-900/70 border-slate-700 text-slate-200"
        )}
      >
        <p>{node.label}</p>
        <p className="mt-1 text-xs uppercase tracking-wide text-slate-400">{node.risk} risk</p>
      </div>
    ))}
  </div>
);

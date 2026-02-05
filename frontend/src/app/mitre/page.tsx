/**
 * ShadowHawk Platform MITRE ATT&CK View
 */
"use client";

import { Card } from "@/components/ui/Card";
import { Heatmap } from "@/components/charts/Heatmap";
import { DataTable } from "@/components/tables/DataTable";
import { fetchMitreCoverage } from "@/lib/api/client";
import { usePolling } from "@/hooks/usePolling";

const MitrePage = () => {
  const { data, loading, error } = usePolling(fetchMitreCoverage, 60000);
  const techniques = data ?? [];

  return (
    <div className="space-y-8">
      <div>
        <h3 className="text-2xl font-semibold text-white">MITRE ATT&CK Coverage</h3>
        <p className="text-sm text-slate-400">Heatmap alignment across tactics and techniques.</p>
      </div>
      {error ? <p className="text-sm text-rose-400">{error}</p> : null}
      <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
        <Card>
          <h4 className="text-lg font-semibold text-white">Kill chain heatmap</h4>
          <p className="mt-2 text-sm text-slate-400">Coverage intensity per technique group.</p>
          <div className="mt-6">
            <Heatmap
              matrix={[
                [20, 45, 70, 55, 80],
                [35, 60, 40, 75, 55],
                [50, 30, 85, 60, 40],
                [65, 45, 35, 70, 90]
              ]}
            />
          </div>
        </Card>
        <Card>
          <h4 className="text-lg font-semibold text-white">Top tactics</h4>
          <p className="mt-2 text-sm text-slate-400">Detection coverage and response readiness.</p>
          <div className="mt-6">
            <DataTable
              data={techniques}
              columns={[
                { key: "id", header: "Tactic" },
                { key: "name", header: "Name" },
                {
                  key: "coverage",
                  header: "Coverage",
                  render: (row) => `${row.coverage}%`
                }
              ]}
            />
          </div>
          {loading ? <p className="mt-4 text-xs text-slate-500">Syncing with MITRE library...</p> : null}
        </Card>
      </div>
      <Card>
        <h4 className="text-lg font-semibold text-white">Recommended improvements</h4>
        <p className="mt-2 text-sm text-slate-400">Immediate coverage upgrades for high-risk tactics.</p>
        <ul className="mt-6 space-y-3 text-sm text-slate-300">
          <li>• Expand telemetry for lateral movement on cloud workloads.</li>
          <li>• Increase deception coverage for credential access campaigns.</li>
          <li>• Automate containment for command-and-control persistence.</li>
        </ul>
      </Card>
    </div>
  );
};

export default MitrePage;

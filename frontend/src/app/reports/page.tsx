/**
 * ShadowHawk Platform Reports View
 */
"use client";

import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { DataTable } from "@/components/tables/DataTable";
import { fetchReports } from "@/lib/api/client";
import { usePolling } from "@/hooks/usePolling";

const ReportsPage = () => {
  const { data, loading, error } = usePolling(fetchReports, 120000);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-2xl font-semibold text-white">Reports</h3>
          <p className="text-sm text-slate-400">Executive-ready reporting with export controls.</p>
        </div>
        <Button variant="secondary">Create custom report</Button>
      </div>
      {error ? <p className="text-sm text-rose-400">{error}</p> : null}
      <Card>
        <h4 className="text-lg font-semibold text-white">Report library</h4>
        <p className="mt-2 text-sm text-slate-400">PDF exports and scheduled delivery.</p>
        <div className="mt-6">
          <DataTable
            data={data ?? []}
            columns={[
              { key: "title", header: "Report" },
              { key: "owner", header: "Owner" },
              { key: "lastRun", header: "Last Run" },
              {
                key: "id",
                header: "Action",
                render: () => <Button variant="ghost">Download PDF</Button>
              }
            ]}
          />
        </div>
        {loading ? <p className="mt-4 text-xs text-slate-500">Syncing report metadata...</p> : null}
      </Card>
      <Card>
        <h4 className="text-lg font-semibold text-white">Report builder</h4>
        <p className="mt-2 text-sm text-slate-400">Drag-and-drop sections for custom audiences.</p>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {[
            "Risk posture summary",
            "SOC operational metrics",
            "Compliance evidence pack"
          ].map((section) => (
            <div key={section} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-200">
              {section}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

export default ReportsPage;

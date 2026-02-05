/**
 * ShadowHawk Platform SOC Analyst Dashboard
 */
"use client";

import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { DataTable } from "@/components/tables/DataTable";
import { TopologyMap } from "@/components/charts/TopologyMap";
import { fetchAlerts, fetchThreatModel } from "@/lib/api/client";
import { usePolling } from "@/hooks/usePolling";
import type { AlertItem } from "@/types";

const severityTone = (severity: AlertItem["severity"]) => {
  switch (severity) {
    case "Critical":
      return "critical";
    case "High":
      return "warning";
    case "Medium":
      return "info";
    default:
      return "success";
  }
};

const ThreatsPage = () => {
  const { data: alertData, loading, error } = usePolling(fetchAlerts, 15000);
  const { data: threatModel } = usePolling(fetchThreatModel, 60000);
  const alerts = alertData ?? [];
  const threatNodes = threatModel ?? [];

  return (
    <div className="space-y-8">
      <div>
        <h3 className="text-2xl font-semibold text-white">SOC Analyst Live View</h3>
        <p className="text-sm text-slate-400">Streaming alerts, findings, and response workflows.</p>
      </div>
      {error ? <p className="text-sm text-rose-400">{error}</p> : null}
      <div className="grid gap-6 lg:grid-cols-[2fr_1fr]">
        <Card>
          <div className="flex items-center justify-between">
            <div>
              <h4 className="text-lg font-semibold text-white">Realtime alert queue</h4>
              <p className="text-sm text-slate-400">Updated every 15 seconds.</p>
            </div>
            <Badge tone="info">Live</Badge>
          </div>
          <div className="mt-6">
            <DataTable
              data={alerts}
              columns={[
                { key: "title", header: "Alert" },
                {
                  key: "severity",
                  header: "Severity",
                  render: (row) => <Badge tone={severityTone(row.severity)}>{row.severity}</Badge>
                },
                { key: "source", header: "Source" },
                { key: "status", header: "Status" }
              ]}
            />
          </div>
          {loading ? <p className="mt-4 text-xs text-slate-500">Refreshing signals...</p> : null}
        </Card>
        <Card>
          <h4 className="text-lg font-semibold text-white">Current investigations</h4>
          <p className="mt-2 text-sm text-slate-400">Focus areas prioritized by severity and business impact.</p>
          <ul className="mt-6 space-y-4 text-sm text-slate-200">
            <li>
              <p className="font-semibold">Credential replay campaign</p>
              <p className="text-xs text-slate-400">Containment running across 18 endpoints.</p>
            </li>
            <li>
              <p className="font-semibold">Insider threat escalation</p>
              <p className="text-xs text-slate-400">Monitoring identity anomalies and privileged access logs.</p>
            </li>
            <li>
              <p className="font-semibold">Cloud API abuse</p>
              <p className="text-xs text-slate-400">Wave 2 protections enabled on ingress nodes.</p>
            </li>
          </ul>
        </Card>
      </div>
      <Card>
        <h4 className="text-lg font-semibold text-white">Threat modeling topology</h4>
        <p className="mt-2 text-sm text-slate-400">Asset exposure and attack surface visualization.</p>
        <div className="mt-6">
          <TopologyMap nodes={threatNodes} />
        </div>
      </Card>
      <Card>
        <h4 className="text-lg font-semibold text-white">Automated response playbooks</h4>
        <p className="mt-2 text-sm text-slate-400">Orchestrated actions across EDR, SOAR, and IAM layers.</p>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {[
            "Containment and quarantine",
            "Credential reset campaign",
            "Network segmentation update"
          ].map((item) => (
            <div key={item} className="rounded-lg border border-slate-800 bg-slate-900/70 p-4 text-sm text-slate-200">
              {item}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

export default ThreatsPage;

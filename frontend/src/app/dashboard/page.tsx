/**
 * ShadowHawk Platform Executive Dashboard
 */
"use client";

import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { TrendChart } from "@/components/charts/TrendChart";
import { fetchDashboardSummary } from "@/lib/api/client";
import { usePolling } from "@/hooks/usePolling";

const DashboardPage = () => {
  const { data, loading, error } = usePolling(fetchDashboardSummary, 60000);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-2xl font-semibold text-white">Executive Command Center</h3>
          <p className="text-sm text-slate-400">Strategic risk posture and compliance health.</p>
        </div>
        <Badge tone="success">Compliance Ready</Badge>
      </div>
      {error ? <p className="text-sm text-rose-400">{error}</p> : null}
      <div className="grid gap-6 lg:grid-cols-4">
        <Card>
          <p className="text-xs uppercase text-slate-400">Enterprise risk score</p>
          <p className="mt-4 text-3xl font-semibold text-white">{loading ? "--" : data?.riskScore}</p>
          <p className="text-sm text-slate-500">Last 24 hours</p>
        </Card>
        <Card>
          <p className="text-xs uppercase text-slate-400">Compliance status</p>
          <p className="mt-4 text-3xl font-semibold text-white">{loading ? "--" : data?.compliance}</p>
          <p className="text-sm text-slate-500">Regulatory alignment</p>
        </Card>
        <Card>
          <p className="text-xs uppercase text-slate-400">Critical alerts</p>
          <p className="mt-4 text-3xl font-semibold text-white">{loading ? "--" : data?.criticalAlerts}</p>
          <p className="text-sm text-slate-500">SOC escalation</p>
        </Card>
        <Card>
          <p className="text-xs uppercase text-slate-400">Active investigations</p>
          <p className="mt-4 text-3xl font-semibold text-white">{loading ? "--" : data?.activeInvestigations}</p>
          <p className="text-sm text-slate-500">Cross-team efforts</p>
        </Card>
      </div>
      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h4 className="text-lg font-semibold text-white">Risk trend</h4>
            <p className="text-sm text-slate-400">Forecasted posture across business units.</p>
          </div>
          <Badge tone="info">Realtime</Badge>
        </div>
        <div className="mt-6">
          <TrendChart data={data?.trend ?? [20, 40, 30, 60, 70, 50]} />
        </div>
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <h4 className="text-lg font-semibold text-white">Compliance readiness</h4>
          <p className="mt-2 text-sm text-slate-400">
            Continuous monitoring across SOC 2, ISO 27001, and internal policy guardrails.
          </p>
          <ul className="mt-6 space-y-3 text-sm text-slate-300">
            <li>• 18 controls auto-remediated this week</li>
            <li>• 6 workflows pending executive approval</li>
            <li>• 3 vendor risks awaiting attestation</li>
          </ul>
        </Card>
        <Card>
          <h4 className="text-lg font-semibold text-white">Board-ready metrics</h4>
          <p className="mt-2 text-sm text-slate-400">
            KPI snapshots tailored for leadership visibility and investor reporting.
          </p>
          <ul className="mt-6 space-y-3 text-sm text-slate-300">
            <li>• Mean time to detect: 4 minutes</li>
            <li>• Mean time to respond: 18 minutes</li>
            <li>• Automated containment: 92%</li>
          </ul>
        </Card>
      </div>
    </div>
  );
};

export default DashboardPage;

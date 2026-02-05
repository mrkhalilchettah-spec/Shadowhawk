/**
 * ShadowHawk Platform Risk Management View
 */
"use client";

import { Card } from "@/components/ui/Card";
import { RiskTable } from "@/components/tables/RiskTable";
import { fetchRisks } from "@/lib/api/client";
import { usePolling } from "@/hooks/usePolling";

const RisksPage = () => {
  const { data, loading, error } = usePolling(fetchRisks, 60000);

  return (
    <div className="space-y-8">
      <div>
        <h3 className="text-2xl font-semibold text-white">Risk Management</h3>
        <p className="text-sm text-slate-400">Risk register, remediation, and governance workflows.</p>
      </div>
      {error ? <p className="text-sm text-rose-400">{error}</p> : null}
      <Card>
        <h4 className="text-lg font-semibold text-white">Risk register</h4>
        <p className="mt-2 text-sm text-slate-400">Key risks mapped to owners and remediation status.</p>
        <div className="mt-6">
          <RiskTable risks={data ?? []} />
        </div>
        {loading ? <p className="mt-4 text-xs text-slate-500">Updating risk register...</p> : null}
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <h4 className="text-lg font-semibold text-white">Remediation workflow</h4>
          <p className="mt-2 text-sm text-slate-400">Workflow status across teams.</p>
          <ul className="mt-6 space-y-3 text-sm text-slate-300">
            <li>• 5 remediation plans in validation</li>
            <li>• 2 executive approvals required</li>
            <li>• 7 automation playbooks scheduled</li>
          </ul>
        </Card>
        <Card>
          <h4 className="text-lg font-semibold text-white">Third-party oversight</h4>
          <p className="mt-2 text-sm text-slate-400">Vendor risk posture and evidence collection.</p>
          <ul className="mt-6 space-y-3 text-sm text-slate-300">
            <li>• 14 vendors in continuous monitoring</li>
            <li>• 3 high-risk attestations pending</li>
            <li>• 1 contract revision required</li>
          </ul>
        </Card>
      </div>
    </div>
  );
};

export default RisksPage;

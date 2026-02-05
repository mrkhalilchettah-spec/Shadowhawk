/**
 * ShadowHawk Platform Correlation View
 */
"use client";

import { Card } from "@/components/ui/Card";
import { TimelineChart } from "@/components/charts/TimelineChart";
import { fetchCorrelationTimeline } from "@/lib/api/client";
import { usePolling } from "@/hooks/usePolling";

const CorrelationPage = () => {
  const { data, error } = usePolling(fetchCorrelationTimeline, 30000);

  return (
    <div className="space-y-8">
      <div>
        <h3 className="text-2xl font-semibold text-white">Correlation View</h3>
        <p className="text-sm text-slate-400">Attack path timeline with evidence linking.</p>
      </div>
      {error ? <p className="text-sm text-rose-400">{error}</p> : null}
      <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr]">
        <Card>
          <h4 className="text-lg font-semibold text-white">Attack path timeline</h4>
          <p className="mt-2 text-sm text-slate-400">Sequenced adversary activity across endpoints.</p>
          <div className="mt-6">
            <TimelineChart events={data ?? []} />
          </div>
        </Card>
        <Card>
          <h4 className="text-lg font-semibold text-white">Linked evidence</h4>
          <p className="mt-2 text-sm text-slate-400">Telemetry sources validating correlation steps.</p>
          <ul className="mt-6 space-y-4 text-sm text-slate-200">
            <li>
              <p className="font-semibold">EDR process tree</p>
              <p className="text-xs text-slate-400">Parent-child execution chains flagged.</p>
            </li>
            <li>
              <p className="font-semibold">Cloud audit logs</p>
              <p className="text-xs text-slate-400">Admin role changes and API misuse.</p>
            </li>
            <li>
              <p className="font-semibold">SIEM correlation rules</p>
              <p className="text-xs text-slate-400">Behavioral anomalies triggered.</p>
            </li>
          </ul>
        </Card>
      </div>
      <Card>
        <h4 className="text-lg font-semibold text-white">Recommended response actions</h4>
        <p className="mt-2 text-sm text-slate-400">Prioritized countermeasures based on path severity.</p>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {[
            "Isolate compromised identity",
            "Run memory forensics",
            "Notify executive stakeholders"
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

export default CorrelationPage;

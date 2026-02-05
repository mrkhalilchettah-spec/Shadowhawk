/**
 * ShadowHawk Platform API Client
 */
import type {
  AlertItem,
  CorrelationEvent,
  DashboardSummary,
  MitreTechnique,
  ReportItem,
  RiskItem,
  ThreatModelNode
} from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "https://api.shadowhawk.local";

const request = async <T,>(path: string): Promise<T> => {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json"
    },
    cache: "no-store"
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return (await response.json()) as T;
};

export const fetchDashboardSummary = async (): Promise<DashboardSummary> => {
  try {
    return await request<DashboardSummary>("/dashboard/summary");
  } catch {
    return {
      riskScore: 78,
      compliance: "94%",
      criticalAlerts: 6,
      activeInvestigations: 12,
      trend: [40, 45, 52, 64, 61, 70, 78]
    };
  }
};

export const fetchAlerts = async (): Promise<AlertItem[]> => {
  try {
    return await request<AlertItem[]>("/alerts/realtime");
  } catch {
    return [
      {
        id: "alert-1",
        title: "Suspicious privilege escalation",
        severity: "Critical",
        source: "Endpoint Sensor",
        status: "Investigating",
        timestamp: "2 min ago"
      },
      {
        id: "alert-2",
        title: "Unusual outbound traffic",
        severity: "High",
        source: "Network Monitor",
        status: "Open",
        timestamp: "7 min ago"
      },
      {
        id: "alert-3",
        title: "Credential reuse detected",
        severity: "Medium",
        source: "IAM Guard",
        status: "Contained",
        timestamp: "18 min ago"
      }
    ];
  }
};

export const fetchThreatModel = async (): Promise<ThreatModelNode[]> => {
  try {
    return await request<ThreatModelNode[]>("/threat-model/nodes");
  } catch {
    return [
      { id: "node-1", label: "Customer Identity", risk: "High" },
      { id: "node-2", label: "Payment Gateway", risk: "Medium" },
      { id: "node-3", label: "Data Lake", risk: "Critical" },
      { id: "node-4", label: "Edge API", risk: "Medium" }
    ];
  }
};

export const fetchMitreCoverage = async (): Promise<MitreTechnique[]> => {
  try {
    return await request<MitreTechnique[]>("/mitre/coverage");
  } catch {
    return [
      { id: "TA0001", name: "Initial Access", coverage: 82 },
      { id: "TA0004", name: "Privilege Escalation", coverage: 74 },
      { id: "TA0005", name: "Defense Evasion", coverage: 68 },
      { id: "TA0008", name: "Lateral Movement", coverage: 59 }
    ];
  }
};

export const fetchCorrelationTimeline = async (): Promise<CorrelationEvent[]> => {
  try {
    return await request<CorrelationEvent[]>("/correlation/timeline");
  } catch {
    return [
      { label: "Phishing payload delivered", timestamp: "09:14 UTC", severity: "medium" },
      { label: "Credential reuse observed", timestamp: "09:32 UTC", severity: "high" },
      { label: "Privilege escalation detected", timestamp: "09:47 UTC", severity: "high" },
      { label: "Data staging blocked", timestamp: "10:05 UTC", severity: "low" }
    ];
  }
};

export const fetchRisks = async (): Promise<RiskItem[]> => {
  try {
    return await request<RiskItem[]>("/risks/register");
  } catch {
    return [
      { name: "Cloud storage exposure", owner: "Risk Ops", impact: "High", status: "In Progress" },
      { name: "Legacy VPN access", owner: "IT Security", impact: "Medium", status: "Mitigated" },
      { name: "Third-party integrations", owner: "Vendor Risk", impact: "High", status: "In Progress" }
    ];
  }
};

export const fetchReports = async (): Promise<ReportItem[]> => {
  try {
    return await request<ReportItem[]>("/reports");
  } catch {
    return [
      { id: "report-1", title: "Quarterly Risk Posture", owner: "Risk Team", lastRun: "Today" },
      { id: "report-2", title: "SOC Metrics", owner: "Security Ops", lastRun: "Yesterday" },
      { id: "report-3", title: "Compliance Readout", owner: "Governance", lastRun: "2 days ago" }
    ];
  }
};

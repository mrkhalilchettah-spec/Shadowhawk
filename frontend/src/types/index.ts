/**
 * ShadowHawk Platform Type Definitions
 */
export type UserRole = "Executive" | "SOC Analyst" | "Risk Manager" | "Threat Hunter";

export type UserProfile = {
  id: string;
  name: string;
  role: UserRole;
  organization: string;
};

export type DashboardSummary = {
  riskScore: number;
  compliance: string;
  criticalAlerts: number;
  activeInvestigations: number;
  trend: number[];
};

export type AlertItem = {
  id: string;
  title: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  source: string;
  status: "Open" | "Investigating" | "Contained";
  timestamp: string;
};

export type ThreatModelNode = {
  id: string;
  label: string;
  risk: string;
};

export type MitreTechnique = {
  id: string;
  name: string;
  coverage: number;
};

export type CorrelationEvent = {
  label: string;
  timestamp: string;
  severity: "low" | "medium" | "high";
};

export type RiskItem = {
  name: string;
  owner: string;
  impact: string;
  status: "Mitigated" | "In Progress";
};

export type ReportItem = {
  id: string;
  title: string;
  owner: string;
  lastRun: string;
};

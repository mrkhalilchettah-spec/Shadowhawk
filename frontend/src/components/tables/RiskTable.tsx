/**
 * ShadowHawk Platform Risk Table
 */
import { Badge } from "@/components/ui/Badge";
import { DataTable } from "@/components/tables/DataTable";
import type { RiskItem } from "@/types";

type RiskTableProps = {
  risks: RiskItem[];
};

export const RiskTable = ({ risks }: RiskTableProps) => (
  <DataTable
    data={risks}
    columns={[
      { key: "name", header: "Risk" },
      { key: "owner", header: "Owner" },
      { key: "impact", header: "Impact" },
      {
        key: "status",
        header: "Status",
        render: (row) => (
          <Badge tone={row.status === "Mitigated" ? "success" : "warning"}>{row.status}</Badge>
        )
      }
    ]}
  />
);

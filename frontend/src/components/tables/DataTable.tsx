/**
 * ShadowHawk Platform Data Table
 */
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

type Column<T> = {
  key: keyof T;
  header: string;
  render?: (row: T) => ReactNode;
};

type DataTableProps<T> = {
  columns: Array<Column<T>>;
  data: T[];
  className?: string;
};

export const DataTable = <T extends Record<string, string | number>>({
  columns,
  data,
  className
}: DataTableProps<T>) => (
  <div className={cn("overflow-hidden rounded-xl border border-slate-800", className)}>
    <table className="w-full text-left text-sm">
      <thead className="bg-slate-900">
        <tr>
          {columns.map((column) => (
            <th key={String(column.key)} className="px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate-400">
              {column.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, index) => (
          <tr key={`row-${index}`} className="border-t border-slate-800 hover:bg-slate-900/70">
            {columns.map((column) => (
              <td key={`${index}-${String(column.key)}`} className="px-4 py-3 text-slate-200">
                {column.render ? column.render(row) : row[column.key]}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

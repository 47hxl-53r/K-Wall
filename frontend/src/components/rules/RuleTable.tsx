
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Edit, Trash2 } from "lucide-react";

interface Rule {
  rule_id: number;
  action: "allow" | "deny";
  direction: "in" | "out";
  protocol: "tcp" | "udp" | "all";
  port: number;
  host: string;
  created_at?: string;
  updated_at?: string;
}

export function RuleTable({ rules, onEdit, onDelete }: { 
  rules: Rule[];
  onEdit: (rule: Rule) => void;
  onDelete: (id: number) => void;
}) {
  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Action</TableHead>
            <TableHead>Direction</TableHead>
            <TableHead>Protocol</TableHead>
            <TableHead>Port</TableHead>
            <TableHead>Host</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((rule) => (
            <TableRow key={rule.rule_id}>
              <TableCell className={rule.action === 'allow' ? 'text-green-600' : 'text-red-600'}>
                {rule.action}
              </TableCell>
              <TableCell>{rule.direction}</TableCell>
              <TableCell>{rule.protocol}</TableCell>
              <TableCell>{rule.port}</TableCell>
              <TableCell>{rule.host}</TableCell>
              <TableCell className="text-right space-x-2">
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => onEdit(rule)}
                >
                  <Edit className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => onDelete(rule.rule_id)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

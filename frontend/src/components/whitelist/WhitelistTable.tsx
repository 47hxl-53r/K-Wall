
import { WhitelistEntry } from "@/services/whitelist-api";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Trash2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

interface WhitelistTableProps {
  whitelist: WhitelistEntry[];
  isLoading: boolean;
  isError: boolean;
  onRemoveIp: (ip: string) => void;
  isRemoving: boolean;
}

export function WhitelistTable({
  whitelist,
  isLoading,
  isError,
  onRemoveIp,
  isRemoving,
}: WhitelistTableProps) {
  if (isLoading) {
    return (
      <div className="border rounded-lg p-8 bg-card">
        <p className="text-center text-muted-foreground">Loading whitelist...</p>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="border rounded-lg p-8 bg-card border-destructive/50">
        <p className="text-center text-destructive">Failed to load whitelist data</p>
      </div>
    );
  }

  if (whitelist.length === 0) {
    return (
      <div className="border rounded-lg p-8 bg-card">
        <p className="text-center text-muted-foreground">No IP addresses in the whitelist</p>
      </div>
    );
  }

  return (
    <div className="border rounded-lg overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>IP Address</TableHead>
            <TableHead>Added</TableHead>
            <TableHead className="w-[100px]">Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {whitelist.map((entry) => (
            <TableRow key={entry.ip_address}>
              <TableCell className="font-mono">{entry.ip_address}</TableCell>
              <TableCell>
                {formatDistanceToNow(new Date(entry.created_at), { addSuffix: true })}
              </TableCell>
              <TableCell>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-8 w-8 p-0 text-destructive hover:text-destructive"
                  onClick={() => onRemoveIp(entry.ip_address)}
                  disabled={isRemoving}
                >
                  <Trash2 className="h-4 w-4" />
                  <span className="sr-only">Remove</span>
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

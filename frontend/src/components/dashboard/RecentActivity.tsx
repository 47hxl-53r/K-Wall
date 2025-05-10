
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { formatDistanceToNow } from "date-fns";
import { getRealtimeLogs } from "@/services/api";
import { Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface RecentActivityProps {
  refreshInterval?: number;
}

function getProtocolIcon(protocol: string) {
  switch (protocol) {
    case "TCP":
    case "6":
    case "2":
      return "🔒";
    case "UDP":
    case "17":
      return "🛡️";
    case "ICMP":
    case "1":
      return "⚠️";
    default:
      return "📡";
  }
}

export function RecentActivity({ refreshInterval = 5000 }: RecentActivityProps) {
  const { data, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ["realtimeLogs", 5, false],
    queryFn: () => getRealtimeLogs(5, false),
    refetchInterval: refreshInterval,
    refetchOnWindowFocus: true,
  });

  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp);
      return formatDistanceToNow(date, { addSuffix: true });
    } catch (error) {
      return timestamp;
    }
  };

  const getProtocolDisplay = (protocol: string) => {
    const protocolMap: Record<string, string> = {
      "1": "ICMP",
      "2": "TCP",
      "6": "TCP",
      "17": "UDP",
    };
    return protocolMap[protocol] || protocol;
  };

  const handleRefresh = async () => {
    try {
      await refetch();
      toast.success("Activity logs refreshed");
    } catch (error) {
      toast.error("Failed to refresh activity logs");
    }
  };

  return (
    <Card className="col-span-1">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
        <CardTitle>Recent Activity</CardTitle>
        <Button 
          variant="ghost" 
          size="sm" 
          onClick={handleRefresh}
          disabled={isLoading || isRefetching}
        >
          <RefreshCw className={`h-4 w-4 ${isRefetching ? "animate-spin" : ""}`} />
          <span className="sr-only">Refresh</span>
        </Button>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[400px] rounded-md">
          {isLoading ? (
            <div className="flex justify-center items-center h-full">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : data?.logs && data.logs.length > 0 ? (
            <div className="space-y-2">
              {data.logs.map((log, index) => (
                <div key={`${log.timestamp_ns}-${index}`} className="log-row p-3 text-xs">
                  <div className="flex justify-between mb-1">
                    <div className="font-mono text-muted-foreground">
                      {formatTimestamp(log.timestamp)}
                    </div>
                    <Badge
                      variant="outline"
                      className={log.action === "ALLOW" ? "border-allow text-allow" : "border-deny text-deny"}
                    >
                      {log.action}
                    </Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <div>
                      <span className="protocol-icon">{getProtocolIcon(log.protocol)}</span> {getProtocolDisplay(log.protocol)}
                    </div>
                    <div className="font-mono">
                      {log.src_ip}:{log.src_port} → {log.dst_ip}:{log.dst_port}
                    </div>
                  </div>
                  <div className="mt-1 text-muted-foreground">{log.reason}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex justify-center items-center h-full text-muted-foreground">
              No recent activity
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}


import { useState, useEffect } from "react";
import { useQueryClient, useQuery } from "@tanstack/react-query";
import { StatsOverview } from "./StatsOverview";
import { RecentActivity } from "./RecentActivity";
import { QuickActions } from "./QuickActions";
import { TrafficCharts } from "./TrafficCharts";
import { getLogStats } from "@/services/api";
import { Loader2, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";

export function DashboardPage() {
  const queryClient = useQueryClient();
  const [refreshInterval, setRefreshInterval] = useState(15000); // 15 seconds refresh interval
  
  // Fetch log statistics
  const { data: logStats, isLoading, isError, error, refetch, isRefetching } = useQuery({
    queryKey: ["logStats"],
    queryFn: getLogStats,
    refetchInterval: refreshInterval,
    refetchOnWindowFocus: true,
  });

  useEffect(() => {
    // Initial data fetch when component mounts
    queryClient.invalidateQueries({ queryKey: ["logStats"] });
  }, [queryClient]);

  const handleManualRefresh = async () => {
    try {
      await refetch();
      toast.success("Dashboard data refreshed");
    } catch (error) {
      toast.error("Failed to refresh dashboard data");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
        <Button 
          variant="outline" 
          size="sm" 
          onClick={handleManualRefresh}
          disabled={isLoading || isRefetching}
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${isRefetching ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center p-8">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      ) : isError ? (
        <div className="text-center p-8 text-destructive">
          <p>Failed to load dashboard data: {(error as Error)?.message || "Unknown error"}</p>
          <Button 
            variant="outline"
            className="mt-4"
            onClick={handleManualRefresh}
          >
            Try Again
          </Button>
        </div>
      ) : (
        <>
          <StatsOverview stats={logStats?.stats} />
          
          <TrafficCharts chartData={logStats?.chart_data} />
          
          <div className="grid gap-4 md:grid-cols-2">
            <RecentActivity refreshInterval={refreshInterval} />
            <QuickActions />
          </div>
        </>
      )}
    </div>
  );
}

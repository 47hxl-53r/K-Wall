
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { RefreshCw, Zap } from "lucide-react";
import { clearLogs } from "@/services/api";
import { toast } from "sonner";

export function QuickActions() {
  const [isClearing, setIsClearing] = useState(false);

  const handleClearLogs = async () => {
    setIsClearing(true);
    try {
      const result = await clearLogs({
        clearRealtime: true,
        clearBlocked: true,
        clearStats: true
      });
      
      if (result.status === "success") {
        toast.success("All logs cleared successfully");
      } else {
        toast.warning("Some logs may not have been cleared");
      }
    } catch (error) {
      toast.error("Failed to clear logs");
    } finally {
      setIsClearing(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Quick Actions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          <div className="pt-2 flex flex-col gap-2">
            <Button variant="outline" className="w-full">
              <RefreshCw className="mr-2 h-4 w-4" />
              Reload Firewall Rules
            </Button>
            <Button 
              variant="outline" 
              className="w-full text-deny border-deny hover:bg-deny/10"
              onClick={handleClearLogs}
              disabled={isClearing}
            >
              <Zap className="mr-2 h-4 w-4" />
              {isClearing ? "Clearing..." : "Clear All Logs"}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

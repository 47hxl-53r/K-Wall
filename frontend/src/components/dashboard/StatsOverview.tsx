
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

interface Stats {
  allowed: number;
  blocked: number;
  blocked_details: {
    reason: string;
    count: number;
  }[];
}

interface StatsOverviewProps {
  stats?: Stats;
}

export function StatsOverview({ stats }: StatsOverviewProps) {
  if (!stats) {
    return (
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Total Traffic</CardTitle>
            <CardDescription>Processed requests</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">0</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Allowed</CardTitle>
            <CardDescription>Permitted connections</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-allow">0</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>Blocked</CardTitle>
            <CardDescription>Denied connections</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-deny">0</div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const totalTraffic = stats.allowed + stats.blocked;

  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Total Traffic</CardTitle>
          <CardDescription>Processed requests</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold">{totalTraffic}</div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Allowed</CardTitle>
          <CardDescription>Permitted connections</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold text-allow">{stats.allowed}</div>
          {totalTraffic > 0 && (
            <p className="text-xs text-muted-foreground mt-1">
              {Math.round((stats.allowed / totalTraffic) * 100)}% of total
            </p>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle>Blocked</CardTitle>
          <CardDescription>Denied connections</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-bold text-deny">{stats.blocked}</div>
          {totalTraffic > 0 && (
            <p className="text-xs text-muted-foreground mt-1">
              {Math.round((stats.blocked / totalTraffic) * 100)}% of total
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

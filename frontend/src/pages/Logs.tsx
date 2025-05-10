
import { Layout } from "@/components/Layout";
// import { LogsManagement } from "@/components/logs/LogsManagement";

export default function Logs() {
  return (
    <Layout>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-display font-bold tracking-tight">Logs Management</h2>
            <p className="text-muted-foreground">View and filter firewall logs in real-time and from the database.</p>
          </div>
        </div>
      </div>
    </Layout>
  );
}


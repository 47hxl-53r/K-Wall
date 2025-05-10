
import { useState, useEffect } from "react";
import { Layout } from "@/components/Layout";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { getConfig } from "@/services/api";
import { toast } from "sonner";
import { ConfigCard } from "@/components/config/ConfigCard";
import { ConfigModeToggle } from "@/components/config/ConfigModeToggle";

const Config = () => {
  const [lockdownMode, setLockdownMode] = useState(false);
  const [stealthMode, setStealthMode] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch current configuration on component mount
  const fetchModeStatuses = async () => {
    setIsLoading(true);
    try {
      const stealthConfig = await getConfig("stealth");
      if (stealthConfig && stealthConfig.status) {
        setStealthMode(stealthConfig.status === "on");
      }
      
      const lockdownConfig = await getConfig("lockdown");
      if (lockdownConfig && lockdownConfig.status) {
        setLockdownMode(lockdownConfig.status === "on");
      }
    } catch (error) {
      console.error("Error fetching configuration status:", error);
      toast.error("Failed to load current configuration");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchModeStatuses();
  }, []);

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h2 className="text-3xl font-bold tracking-tight">Configuration</h2>
        </div>
        
        <ConfigCard 
          title="Firewall Modes" 
          description="Configure special operation modes for the firewall"
        >
          {isLoading ? (
            <div className="flex justify-center items-center py-8">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
            </div>
          ) : (
            <>
              <ConfigModeToggle
                name="lockdown"
                icon={AlertTriangle}
                title="Lockdown Mode"
                description="When enabled, blocks all non-essential traffic to and from your system. Use this in emergency situations when your system might be under attack."
                enableMessage="Warning: Enabling Lockdown Mode will block all non-essential traffic to and from your system. Only critical services and connections will be allowed. This may disrupt normal operations."
                disableMessage="Disabling Lockdown Mode will return your firewall to normal operation, allowing all traffic that doesn't violate specific rules."
                isEnabled={lockdownMode}
                iconClassName="text-deny"
                onStatusChange={(status) => setLockdownMode(status)}
              />

              <ConfigModeToggle
                name="stealth"
                icon={ShieldAlert}
                title="Stealth Mode"
                description="When enabled, your system will not respond to port scans, making it more difficult for potential attackers to discover services running on your system."
                enableMessage="Enabling Stealth Mode will prevent your system from responding to port scans and similar probing techniques. This makes your system more difficult to discover on the network, increasing security but potentially affecting some network diagnostics tools."
                disableMessage="Disabling Stealth Mode will allow your system to respond normally to port scans and network discovery. This is the standard behavior for most systems."
                isEnabled={stealthMode}
                iconClassName="text-secondary"
                onStatusChange={(status) => setStealthMode(status)}
              />
            </>
          )}
        </ConfigCard>
      </div>
    </Layout>
  );
};

export default Config;


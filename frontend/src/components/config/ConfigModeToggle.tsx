
import { useState } from "react";
import { Switch } from "@/components/ui/switch";
import { LucideIcon } from "lucide-react";
import { ConfirmationDialog } from "./ConfirmationDialog";
import { manageConfig } from "@/services/api";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Terminal } from "lucide-react";

interface ConfigModeToggleProps {
  name: "lockdown" | "stealth";
  icon: LucideIcon;
  title: string;
  description: string;
  enableMessage: string;
  disableMessage: string;
  isEnabled: boolean;
  iconClassName?: string;
  onStatusChange: (status: boolean) => void;
}

export const ConfigModeToggle = ({
  name,
  icon: Icon,
  title,
  description,
  enableMessage,
  disableMessage,
  isEnabled,
  iconClassName = "",
  onStatusChange,
}: ConfigModeToggleProps) => {
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [pendingState, setPendingState] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  const handleToggleClick = (enabled: boolean) => {
    setPendingState(enabled);
    setIsDialogOpen(true);
  };

  const handleConfirm = async () => {
    setIsLoading(true);
    try {
      await manageConfig(name, pendingState ? "on" : "off");
      onStatusChange(pendingState);
      toast.success(`${title} ${pendingState ? 'enabled' : 'disabled'}`);
      
      // Show a special warning toast when lockdown mode is enabled
      if (name === "lockdown" && pendingState) {
        toast.warning(
          "WARNING: This web dashboard will become inaccessible in lockdown mode. To disable, you'll need to use curl or another tool to directly call the API server.",
          { duration: 10000 } // Show for 10 seconds
        );
      }
      
      setIsDialogOpen(false);
    } catch (error) {
      toast.error(`Failed to update ${name} mode`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      <div className="flex items-center justify-between border-b last:border-b-0 pb-4 last:pb-0">
        <div className="flex items-center gap-2">
          <Icon className={`h-5 w-5 ${iconClassName}`} />
          <div>
            <div className="font-medium text-lg">{title}</div>
            <div className="text-sm text-muted-foreground">
              {description}
            </div>
          </div>
        </div>
        <Switch
          checked={isEnabled}
          onCheckedChange={handleToggleClick}
          className={isEnabled && name === "lockdown" ? "bg-deny" : ""}
          disabled={isLoading}
        />
      </div>

      {/* Special warning for lockdown mode */}
      {name === "lockdown" && isEnabled && (
        <Alert variant="destructive" className="mt-2 mb-4">
          <Terminal className="h-4 w-4" />
          <AlertTitle>Web Dashboard Access Warning</AlertTitle>
          <AlertDescription>
            You currently have lockdown mode enabled. If you lose access to this dashboard, 
            you can disable lockdown mode using the following command:
            <pre className="mt-2 p-2 bg-black/10 rounded text-xs overflow-x-auto">
              curl -X POST http://localhost:9877/api/manage -H "Content-Type: application/json" -d {'{"config":{"lockdown":"off"}}'}
            </pre>
          </AlertDescription>
        </Alert>
      )}

      <ConfirmationDialog
        isOpen={isDialogOpen}
        setIsOpen={setIsDialogOpen}
        title={`${pendingState ? "Enable" : "Disable"} ${title}`}
        description={pendingState && name === "lockdown" ? 
          enableMessage + "\n\nWARNING: This will make the web dashboard inaccessible! You'll need to use curl or another tool to disable lockdown mode." : 
          pendingState ? enableMessage : disableMessage}
        icon={<Icon className={`h-5 w-5 ${iconClassName}`} />}
        onConfirm={handleConfirm}
        isLoading={isLoading}
      />
    </>
  );
};


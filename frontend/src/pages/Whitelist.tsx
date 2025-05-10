
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Layout } from "@/components/Layout";
import { WhitelistTable } from "@/components/whitelist/WhitelistTable";
import { WhitelistForm } from "@/components/whitelist/WhitelistForm";
import { getWhitelist, manageWhitelist } from "@/services/whitelist-api";
import { toast } from "sonner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Info } from "lucide-react";

const Whitelist = () => {
  const queryClient = useQueryClient();
  
  // Fetch whitelist data
  const { data, isLoading, isError } = useQuery({
    queryKey: ['whitelist'],
    queryFn: getWhitelist,
  });

  // Add IP mutation
  const addIpMutation = useMutation({
    mutationFn: (ip: string) => manageWhitelist("add", ip),
    onSuccess: (data) => {
      toast.success(data.message || "IP address added to whitelist");
      queryClient.invalidateQueries({ queryKey: ['whitelist'] });
    },
    onError: (error: any) => {
      toast.error(error.message || "Failed to add IP address");
    }
  });

  // Remove IP mutation
  const removeIpMutation = useMutation({
    mutationFn: (ip: string) => manageWhitelist("remove", ip),
    onSuccess: (data) => {
      toast.success(data.message || "IP address removed from whitelist");
      queryClient.invalidateQueries({ queryKey: ['whitelist'] });
    },
    onError: (error: any) => {
      toast.error(error.message || "Failed to remove IP address");
    }
  });

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h2 className="text-3xl font-bold tracking-tight">IP Whitelist</h2>
        </div>
        
        <Alert className="bg-card border-primary/20">
          <Info className="h-4 w-4" />
          <AlertDescription>
            IP addresses in the whitelist will bypass all firewall rules and restrictions. 
            Only add trusted IP addresses that require unrestricted access to your network.
          </AlertDescription>
        </Alert>
        
        <div className="grid gap-6">
          <WhitelistForm 
            onAddIp={(ip) => addIpMutation.mutate(ip)}
            isLoading={addIpMutation.isPending}
          />
          
          <WhitelistTable
            whitelist={data?.whitelist || []}
            isLoading={isLoading}
            isError={isError}
            onRemoveIp={(ip) => removeIpMutation.mutate(ip)}
            isRemoving={removeIpMutation.isPending}
          />
        </div>
      </div>
    </Layout>
  );
};

export default Whitelist;

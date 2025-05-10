
import { useState } from "react";
import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Plus, LayoutTemplate } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { RuleTable } from "@/components/rules/RuleTable";
import { RuleForm } from "@/components/rules/RuleForm";
import { TemplatesDialog } from "@/components/rules/TemplatesDialog";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getRules, manageRule, getNextRuleId, deleteRule, FirewallRule } from "@/services/rules-api";
import { toast } from "sonner";

// Use the FirewallRule type from rules-api.ts to ensure type compatibility
type Rule = FirewallRule & {
  rule_id: number; // Make rule_id required for Rule
};

const Rules = () => {
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [isTemplatesDialogOpen, setIsTemplatesDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const queryClient = useQueryClient();

  const { data: rulesData = { rules: [] }, isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: getRules,
  });

  // Ensure rules are properly typed with required rule_id
  const rules = rulesData.rules
    ? rulesData.rules.filter(rule => rule.rule_id !== undefined) as Rule[]
    : [];

  const mutation = useMutation({
    mutationFn: async (variables: { 
      operation: "add" | "update"; 
      ruleData: Partial<Rule>
    }) => {
      return manageRule(variables.operation, variables.ruleData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      setIsDialogOpen(false);
      setEditingRule(null);
      toast.success(editingRule ? "Rule updated successfully" : "Rule added successfully");
    },
    onError: (error) => {
      toast.error("Failed to save rule");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (ruleId: number) => {
      return deleteRule(ruleId);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      toast.success("Rule deleted successfully");
    },
    onError: (error) => {
      toast.error("Failed to delete rule");
    },
  });

  const nextRuleIdQuery = useQuery({
    queryKey: ['nextRuleId'],
    queryFn: getNextRuleId,
    enabled: false, // Don't run this query automatically
  });

  const handleEdit = (rule: Rule) => {
    setEditingRule(rule);
    setIsDialogOpen(true);
  };

  const handleDelete = async (rule_id: number) => {
    deleteMutation.mutate(rule_id);
  };

  const handleSubmit = async (data: Omit<Rule, "created_at" | "updated_at">) => {
    const operation = editingRule ? "update" : "add";
    let ruleData = { ...data };
    
    // If adding a new rule, get the next rule_id
    if (operation === "add") {
      try {
        const response = await nextRuleIdQuery.refetch();
        if (response.data) {
          ruleData.rule_id = response.data.rule_id;
        }
      } catch (error) {
        toast.error("Failed to get next rule ID");
        return;
      }
    }
    
    // Remove created_at and updated_at if they exist
    if ('created_at' in ruleData) delete ruleData.created_at;
    if ('updated_at' in ruleData) delete ruleData.updated_at;
    
    mutation.mutate({ 
      operation, 
      ruleData 
    });
  };

  const handleApplyTemplate = async (templateRules: Omit<Rule, "rule_id" | "created_at" | "updated_at">[]) => {
    // Process template rules sequentially
    for (const ruleTemplate of templateRules) {
      try {
        // Get next rule ID
        const response = await nextRuleIdQuery.refetch();
        if (!response.data) {
          toast.error("Failed to get next rule ID");
          return;
        }
        
        const ruleData = { 
          ...ruleTemplate, 
          rule_id: response.data.rule_id 
        };
        
        // Add the rule
        await manageRule("add", ruleData);
      } catch (error) {
        toast.error("Error applying template rule");
        return;
      }
    }
    
    // Refresh the rules list
    queryClient.invalidateQueries({ queryKey: ['rules'] });
    toast.success("Template applied successfully");
    setIsTemplatesDialogOpen(false);
  };

  return (
    <Layout>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <h2 className="text-3xl font-bold tracking-tight">Rule Management</h2>
          <div className="flex space-x-2">
            <Button 
              variant="outline" 
              onClick={() => setIsTemplatesDialogOpen(true)}
            >
              <LayoutTemplate className="mr-2 h-4 w-4" />
              Use Templates
            </Button>
            <Button onClick={() => setIsDialogOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              Add Rule
            </Button>
          </div>
        </div>

        {isLoading ? (
          <div className="flex justify-center">
            <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
          </div>
        ) : (
          <RuleTable
            rules={rules}
            onEdit={handleEdit}
            onDelete={handleDelete}
          />
        )}

        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {editingRule ? "Edit Rule" : "Add New Rule"}
              </DialogTitle>
            </DialogHeader>
            <RuleForm
              initialData={editingRule || undefined}
              onSubmit={handleSubmit}
              onCancel={() => setIsDialogOpen(false)}
            />
          </DialogContent>
        </Dialog>
        
        {/* Templates Dialog */}
        <TemplatesDialog 
          isOpen={isTemplatesDialogOpen}
          onOpenChange={setIsTemplatesDialogOpen}
          onApplyTemplate={handleApplyTemplate}
        />
      </div>
    </Layout>
  );
};

export default Rules;

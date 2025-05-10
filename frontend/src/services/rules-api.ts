
import { apiFetch, ApiResponse } from "./api";

/**
 * Interface representing a firewall rule
 */
export interface FirewallRule {
  rule_id?: number;
  action: "allow" | "deny";
  direction: "in" | "out";
  protocol: "tcp" | "udp" | "all";
  port: number;
  host: string;
  created_at?: string;
  updated_at?: string;
}

/**
 * Gets the current firewall rules
 */
export async function getRules() {
  return apiFetch<{ rules: FirewallRule[] }>("/rules");
}

/**
 * Gets the next available rule ID
 */
export async function getNextRuleId() {
  return apiFetch<{ rule_id: number }>("/rules/next_rule_id");
}

/**
 * Adds or updates a firewall rule
 * 
 * @param operation Operation to perform ("add" or "update")
 * @param ruleData Rule data
 */
export async function manageRule(operation: "add" | "update", ruleData: Partial<FirewallRule>) {
  return apiFetch<ApiResponse<any>>("/manage", {
    method: "POST",
    body: JSON.stringify({
      rule: {
        operation,
        ...ruleData,
      },
    }),
  });
}

/**
 * Deletes a firewall rule
 * 
 * @param ruleId ID of the rule to delete
 */
export async function deleteRule(ruleId: number) {
  return apiFetch<ApiResponse<any>>(`/delete/${ruleId}`, {
    method: "DELETE",
  });
}

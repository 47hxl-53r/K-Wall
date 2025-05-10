
import { apiFetch, ApiResponse } from "./api";

export interface WhitelistEntry {
  ip_address: string;
  created_at: string;
}

export interface WhitelistResponse {
  status: string;
  message: string;
  whitelist?: WhitelistEntry[];
}

/**
 * Gets the current whitelist
 */
export async function getWhitelist(): Promise<WhitelistResponse> {
  return apiFetch<WhitelistResponse>("/whitelist");
}

/**
 * Adds or removes an IP address from the whitelist
 * 
 * @param operation Operation to perform ("add" or "remove")
 * @param ip_address IP address to manage
 */
export async function manageWhitelist(operation: "add" | "remove", ip_address: string): Promise<ApiResponse<any>> {
  return apiFetch<ApiResponse<any>>("/whitelist/manage", {
    method: "POST",
    body: JSON.stringify({
      operation,
      ip_address,
    }),
  });
}

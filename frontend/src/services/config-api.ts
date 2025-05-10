
import { apiFetch, ApiResponse } from "./api";

/**
 * Gets the current status of a specific configuration
 * 
 * @param type Configuration type ("lockdown" or "stealth")
 */
export async function getConfig(type: "lockdown" | "stealth"): Promise<{config_type: string, status: string, updated_at: string}> {
  return apiFetch<{config_type: string, status: string, updated_at: string}>(`/config/${type}`);
}

/**
 * Changes a configuration setting
 * 
 * @param type Configuration type to change
 * @param status New status ("on" or "off")
 */
export async function manageConfig(type: "lockdown" | "stealth", status: "on" | "off"): Promise<ApiResponse<any>> {
  return apiFetch<ApiResponse<any>>("/manage", {
    method: "POST",
    body: JSON.stringify({
      config: {
        [type]: status,
      },
    }),
  });
}


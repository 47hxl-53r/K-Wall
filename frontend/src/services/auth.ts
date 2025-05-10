
import { apiFetch, ApiResponse } from "./api";
import { toast } from "sonner";

export interface User {
  username: string;
}

export async function login(username: string, password: string): Promise<User | null> {
  try {
    const response = await apiFetch<ApiResponse<User>>("/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Prevent browser from showing default auth popup
        "X-Requested-With": "XMLHttpRequest" 
      },
      body: JSON.stringify({
        username,
        password,
      }),
      // Make sure we don't include credentials that might trigger browser auth
      credentials: "omit"
    });

    // Check for success response and handle the server's format where username is in response.user
    if (response.status === "success") {
      // Create a proper User object from the response.user string
      if (response.user) {
        const user: User = { username: response.user };
        toast.success("Login successful");
        saveUser(user);
        return user;
      } else if (response.data) {
        // Fallback to the original format if it exists
        toast.success("Login successful");
        saveUser(response.data);
        return response.data;
      }
    }
    
    toast.error("Login failed. Please check your credentials.");
    return null;
  } catch (error) {
    toast.error("Login failed. Please check your credentials.");
    return null;
  }
}

export async function logout(): Promise<boolean> {
  try {
    // In a real app, you'd call a logout endpoint
    // For now, we'll just simulate success
    
    // Clear session storage
    sessionStorage.removeItem("user");
    
    return true;
  } catch (error) {
    return false;
  }
}

export function getCurrentUser(): User | null {
  const userJson = sessionStorage.getItem("user");
  if (!userJson) return null;
  
  try {
    return JSON.parse(userJson) as User;
  } catch (e) {
    return null;
  }
}

export function saveUser(user: User): void {
  sessionStorage.setItem("user", JSON.stringify(user));
}


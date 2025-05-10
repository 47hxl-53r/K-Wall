
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { LogOut, Bell, Shield } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { useState } from "react";

export function Header() {
  const { user, logout } = useAuth();
  const [alertCount] = useState(3); // Mock alert count

  return (
    <header className="h-16 border-b border-border bg-card flex items-center justify-between px-4 md:px-6">
      <div className="flex items-center gap-2">
        <Shield className="h-6 w-6 text-primary" />
        <h1 className="text-xl font-display font-bold hidden md:block">K-Wall</h1>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="relative">
          <Button variant="ghost" size="icon" className="relative">
            <Bell className="h-5 w-5" />
            {alertCount > 0 && (
              <Badge className="absolute -top-1 -right-1 h-5 w-5 flex items-center justify-center p-0 bg-deny">
                {alertCount}
              </Badge>
            )}
          </Button>
        </div>
        
        <div className="hidden md:flex items-center gap-2">
          <div className="text-sm opacity-80">Logged in as</div>
          <div className="font-bold text-primary">{user?.username || "Admin"}</div>
        </div>
        
        <Button variant="ghost" size="icon" onClick={() => logout()}>
          <LogOut className="h-5 w-5" />
        </Button>
      </div>
    </header>
  );
}

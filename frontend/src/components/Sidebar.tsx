
import { Link, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  BarChart,
  Shield,
  List,
  Settings,
  Home,
  Database,
} from "lucide-react";

const navItems = [
  {
    title: "Dashboard",
    icon: Home,
    href: "/dashboard",
  },
  {
    title: "Rules",
    icon: Shield,
    href: "/rules",
  },
  {
    title: "Whitelist",
    icon: List,
    href: "/whitelist",
  },
  {
    title: "Logs",
    icon: Database,
    href: "/logs",
  },
  {
    title: "Configuration",
    icon: Settings,
    href: "/config",
  },
];

export function Sidebar() {
  const location = useLocation();

  return (
    <aside className="w-14 md:w-56 h-screen bg-card border-r border-border flex flex-col fixed left-0 top-0 z-30">
      <div className="p-3 md:p-4 border-b border-border">
        <div className="flex items-center justify-center md:justify-start gap-2">
          <Shield className="h-8 w-8 text-primary" />
          <span className="hidden md:block text-lg font-display font-bold">K-Wall</span>
        </div>
      </div>
      
      <nav className="flex-1 overflow-auto p-2">
        <div className="space-y-1">
          {navItems.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <Link
                key={item.href}
                to={item.href}
                className={cn(
                  "flex items-center justify-center md:justify-start gap-3 px-2 py-2 rounded-md text-sm transition-colors",
                  isActive
                    ? "bg-primary/10 text-primary font-medium"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                <item.icon className="h-5 w-5 flex-shrink-0" />
                <span className="hidden md:block">{item.title}</span>
              </Link>
            );
          })}
        </div>
      </nav>

      <div className="p-3 md:p-4 border-t border-border">
        <div className="hidden md:block text-xs text-muted-foreground mb-2">
          System Status
        </div>
        <div className="flex justify-center md:justify-start items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-allow animate-pulse-subtle"></div>
          <span className="hidden md:inline text-xs">Online</span>
        </div>
      </div>
    </aside>
  );
}

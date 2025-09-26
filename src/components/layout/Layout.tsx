import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Shield,
  Server,
  Settings,
  FileText,
  Moon,
  Sun,
  Info,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { APP_VERSION } from '@/lib/app-version';

interface LayoutProps {
  darkMode: boolean;
  onToggleDarkMode: () => void;
  proxyRunning: boolean;
  children?: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ darkMode, onToggleDarkMode, proxyRunning, children }) => {
  const location = useLocation();

  const navItems = [
    {
      path: '/auth',
      icon: Shield,
      label: 'Authentication',
      description: 'OAuth token management'
    },
    {
      path: '/proxy',
      icon: Server,
      label: 'Proxy Control',
      description: 'Start/stop proxy server'
    },
    {
      path: '/settings',
      icon: Settings,
      label: 'Settings',
      description: 'Configuration options'
    },
    {
      path: '/logs',
      icon: FileText,
      label: 'Logs',
      description: 'View server logs'
    },
    {
      path: '/about',
      icon: Info,
      label: 'About',
      description: 'Version, links, disclaimer'
    }
  ];

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <div className="w-64 border-r bg-card/50 flex flex-col">
        {/* Header */}
        <div className="p-6 border-b">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-lg font-semibold">MaxProxy</h1>
            </div>
            <div className="flex items-center gap-2">
              <Badge
                variant={proxyRunning ? "success" : "secondary"}
                className="text-xs"
              >
                {proxyRunning ? "Running" : "Stopped"}
              </Badge>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4">
          <div className="space-y-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;

              return (
                <Link key={item.path} to={item.path}>
                  <div className={cn(
                    "flex items-center gap-3 p-3 rounded-lg transition-colors hover:bg-accent hover:text-accent-foreground",
                    isActive && "bg-accent text-accent-foreground"
                  )}>
                    <Icon className="h-4 w-4" />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium">{item.label}</div>
                      <div className="text-xs text-muted-foreground truncate">
                        {item.description}
                      </div>
                    </div>
                  </div>
                </Link>
              );
            })}
          </div>
        </nav>

        {/* Footer */}
        <div className="p-4 border-t">
          <div className="flex items-center justify-between">
            <div className="text-xs text-muted-foreground">
              v{APP_VERSION}
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={onToggleDarkMode}
              className="h-8 w-8"
            >
              {darkMode ? (
                <Sun className="h-4 w-4" />
              ) : (
                <Moon className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <main className="flex-1 overflow-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;

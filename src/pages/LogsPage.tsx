import React, { useState, useRef, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  FileText,
  Trash2,
  Download,
  Search,
  RefreshCw,
  ScrollText,
  Terminal,
  Clock,
  Filter,
  X
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { getLogs, clearLogs } from '@/lib/api';

const LogsPage: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const [message, setMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);

  // Query for logs with auto-refresh
  const { data: logsData, refetch: refetchLogs } = useQuery({
    queryKey: ['logs'],
    queryFn: getLogs,
    refetchInterval: 2000, // Refresh every 2 seconds for real-time effect
  });

  const clearLogsMutation = useMutation({
    mutationFn: clearLogs,
    onSuccess: (result) => {
      if (result.success) {
        setMessage({ type: 'success', text: 'Logs cleared successfully!' });
        refetchLogs();
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to clear logs' });
      }
    },
  });

  const logs = logsData?.data || [];

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  // Check if user has scrolled up manually
  useEffect(() => {
    const container = logsContainerRef.current;
    if (!container) return;

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = container;
      const isAtBottom = scrollTop + clientHeight >= scrollHeight - 50;
      setAutoScroll(isAtBottom);
    };

    container.addEventListener('scroll', handleScroll);
    return () => container.removeEventListener('scroll', handleScroll);
  }, []);

  const handleClearLogs = () => {
    if (confirm('Are you sure you want to clear all logs? This action cannot be undone.')) {
      setMessage(null);
      clearLogsMutation.mutate();
    }
  };

  const handleExportLogs = () => {
    const logsText = logs.join('\n');
    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maxproxy-logs-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setMessage({ type: 'info', text: 'Logs exported successfully!' });
  };

  const handleScrollToBottom = () => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
      setAutoScroll(true);
    }
  };

  const filteredLogs = logs.filter((log) =>
    searchTerm === '' || log.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const getLogLevel = (log: string): 'error' | 'warning' | 'info' | 'debug' => {
    const lowercaseLog = log.toLowerCase();
    if (lowercaseLog.includes('error') || lowercaseLog.includes('failed')) return 'error';
    if (lowercaseLog.includes('warning') || lowercaseLog.includes('warn')) return 'warning';
    if (lowercaseLog.includes('debug')) return 'debug';
    return 'info';
  };

  const formatLogEntry = (log: string, index: number) => {
    const level = getLogLevel(log);
    const levelColors = {
      error: 'text-red-600 dark:text-red-400',
      warning: 'text-yellow-600 dark:text-yellow-400',
      info: 'text-blue-600 dark:text-blue-400',
      debug: 'text-gray-500 dark:text-gray-400',
    };

    const levelBadges = {
      error: 'destructive',
      warning: 'warning',
      info: 'default',
      debug: 'secondary',
    } as const;

    return (
      <div
        key={index}
        className="flex items-start gap-3 py-2 px-3 hover:bg-muted/50 rounded text-sm font-mono border-l-2 border-transparent hover:border-primary/20 transition-colors"
      >
        <div className="flex-shrink-0 w-12 text-xs text-muted-foreground">
          {String(index + 1).padStart(3, '0')}
        </div>
        <div className="flex-shrink-0">
          <Badge variant={levelBadges[level]} className="text-xs px-1.5 py-0">
            {level.toUpperCase()}
          </Badge>
        </div>
        <div className={`flex-1 break-all ${levelColors[level]}`}>
          {log}
        </div>
      </div>
    );
  };

  return (
    <div className="max-w-full mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Logs</h1>
        <p className="text-muted-foreground">
          Monitor your proxy server activity and debug information in real-time.
        </p>
      </div>

      {/* Status Alert */}
      {message && (
        <Alert variant={message.type === 'error' ? 'destructive' : message.type === 'success' ? 'success' : 'default'}>
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
      )}

      {/* Controls */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="h-5 w-5" />
                Server Logs
                <Badge variant="secondary" className="text-xs">
                  {logs.length} entries
                </Badge>
              </CardTitle>
              <CardDescription>
                Real-time proxy server activity and debug information
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <div className="flex items-center gap-2 flex-1 min-w-[200px]">
              <Search className="h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search logs..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="flex-1"
              />
              {searchTerm && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSearchTerm('')}
                  className="px-2"
                >
                  <X className="h-4 w-4" />
                </Button>
              )}
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetchLogs()}
                className="flex items-center gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={handleScrollToBottom}
                disabled={autoScroll}
                className="flex items-center gap-2"
              >
                <ScrollText className="h-4 w-4" />
                Scroll to Bottom
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={handleExportLogs}
                disabled={logs.length === 0}
                className="flex items-center gap-2"
              >
                <Download className="h-4 w-4" />
                Export
              </Button>

              <Button
                variant="destructive"
                size="sm"
                onClick={handleClearLogs}
                disabled={clearLogsMutation.isPending || logs.length === 0}
                className="flex items-center gap-2"
              >
                <Trash2 className="h-4 w-4" />
                {clearLogsMutation.isPending ? 'Clearing...' : 'Clear'}
              </Button>
            </div>
          </div>

          {searchTerm && (
            <div className="mb-4">
              <Badge variant="outline" className="flex items-center gap-2 w-fit">
                <Filter className="h-3 w-3" />
                Showing {filteredLogs.length} of {logs.length} entries
              </Badge>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Logs Display */}
      <Card>
        <CardContent className="p-0">
          <div
            ref={logsContainerRef}
            className="h-[600px] overflow-y-auto bg-muted/20 border-t"
          >
            {filteredLogs.length > 0 ? (
              <div className="p-0">
                {filteredLogs.map((log, index) => formatLogEntry(log, index))}
                <div ref={logsEndRef} className="h-1" />
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                <FileText className="h-12 w-12 mb-4 opacity-50" />
                <p className="text-lg font-medium mb-2">
                  {searchTerm ? 'No matching logs found' : 'No logs available'}
                </p>
                <p className="text-sm max-w-md text-center">
                  {searchTerm
                    ? `Try adjusting your search term "${searchTerm}" or clear the filter to see all logs.`
                    : 'Server logs will appear here when the proxy server is running and processing requests.'}
                </p>
                {searchTerm && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSearchTerm('')}
                    className="mt-4 flex items-center gap-2"
                  >
                    <X className="h-4 w-4" />
                    Clear Filter
                  </Button>
                )}
              </div>
            )}
          </div>

          {/* Footer with status indicators */}
          <div className="flex items-center justify-between px-4 py-2 bg-muted/30 border-t text-xs text-muted-foreground">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${logs.length > 0 ? 'bg-green-500' : 'bg-gray-400'}`} />
                <span>{logs.length > 0 ? 'Active' : 'No Data'}</span>
              </div>
              <div className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                <span>Updates every 2 seconds</span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {searchTerm && (
                <span>Filtered: {filteredLogs.length}/{logs.length}</span>
              )}
              <div className="flex items-center gap-1">
                <ScrollText className="h-3 w-3" />
                <span>Auto-scroll: {autoScroll ? 'On' : 'Off'}</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Log Levels Legend */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Log Levels</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="flex items-center gap-2">
              <Badge variant="destructive" className="text-xs">ERROR</Badge>
              <span className="text-sm text-muted-foreground">Critical errors</span>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="warning" className="text-xs">WARNING</Badge>
              <span className="text-sm text-muted-foreground">Important notices</span>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="default" className="text-xs">INFO</Badge>
              <span className="text-sm text-muted-foreground">General information</span>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="secondary" className="text-xs">DEBUG</Badge>
              <span className="text-sm text-muted-foreground">Debug information</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default LogsPage;
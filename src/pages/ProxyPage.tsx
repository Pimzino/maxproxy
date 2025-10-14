import React, { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  Server,
  Play,
  Square,
  Wifi,
  WifiOff,
  Copy,
  AlertTriangle,
  CheckCircle,
  Globe,
  Zap,
  Activity,
  Info,
  Lock
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useAppContext } from '@/contexts/AppContext';
import {
  startProxyServer,
  stopProxyServer,
  getProxyStatus,
  getProxyConfig,
  getTokenStatus
} from '@/lib/api';

const ProxyPage: React.FC = () => {
  const { state, refreshAppState } = useAppContext();
  const [message, setMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  // Queries
  const { data: proxyStatusData, refetch: refetchProxyStatus } = useQuery({
    queryKey: ['proxyStatus'],
    queryFn: getProxyStatus,
    refetchInterval: 3000, // Refresh every 3 seconds
  });

  const { data: proxyConfigData } = useQuery({
    queryKey: ['proxyConfig'],
    queryFn: getProxyConfig,
  });

  const { data: tokenStatusData } = useQuery({
    queryKey: ['tokenStatus'],
    queryFn: getTokenStatus,
  });

  // Mutations
  const startServerMutation = useMutation({
    mutationFn: startProxyServer,
    onSuccess: (result) => {
      if (result.success) {
        setMessage({ type: 'success', text: 'Proxy server started successfully!' });
        refetchProxyStatus();
        refreshAppState();
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to start proxy server' });
      }
    },
  });

  const stopServerMutation = useMutation({
    mutationFn: stopProxyServer,
    onSuccess: (result) => {
      if (result.success) {
        setMessage({ type: 'success', text: 'Proxy server stopped successfully!' });
        refetchProxyStatus();
        refreshAppState();
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to stop proxy server' });
      }
    },
  });

  const proxyRunning = proxyStatusData?.data ?? state.proxyRunning;
  const proxyConfig = proxyConfigData?.data ?? state.proxyConfig;
  const tokenStatus = tokenStatusData?.data ?? state.tokenStatus;
  const hasValidAuth = tokenStatus?.has_tokens && !tokenStatus?.is_expired;

  const handleStartServer = () => {
    setMessage(null);
    startServerMutation.mutate();
  };

  const handleStopServer = () => {
    setMessage(null);
    stopServerMutation.mutate();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setMessage({ type: 'info', text: 'Copied to clipboard!' });
  };

  const getServerUrl = () => {
    if (!proxyConfig) return '';
    const host = proxyConfig.bind_address === '0.0.0.0' ? 'localhost' : proxyConfig.bind_address;
    const scheme = proxyConfig.enable_tls ? 'https' : 'http';
    return `${scheme}://${host}:${proxyConfig.port}`;
  };

  const getStatusIcon = () => {
    if (proxyRunning) {
      return <Wifi className="h-5 w-5 text-green-500" />;
    }
    return <WifiOff className="h-5 w-5 text-gray-400" />;
  };

  const getStatusBadge = () => {
    if (proxyRunning) {
      return <Badge variant="success" className="flex items-center gap-1">
        <Activity className="h-3 w-3" />
        Running
      </Badge>;
    }
    return <Badge variant="secondary">Stopped</Badge>;
  };

  return (
    <div className="max-w-full mx-auto space-y-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">Proxy Control</h1>
        <p className="text-muted-foreground">
          Start, stop, and monitor your proxy server for Anthropic API access.
        </p>
      </div>

      {/* Status Alert */}
      {message && (
        <Alert variant={message.type === 'error' ? 'destructive' : message.type === 'success' ? 'success' : 'default'}>
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
      )}

      {/* Authentication Warning */}
      {!hasValidAuth && (
        <Alert variant="warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            You need valid authentication tokens to use the proxy server.
            Please <a href="/auth" className="underline font-medium">authenticate first</a>.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Server Status Card */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {getStatusIcon()}
                <div>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    Server Status
                    {getStatusBadge()}
                  </CardTitle>
                  <CardDescription>
                    Current proxy server state and connection details
                  </CardDescription>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {proxyConfig && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="space-y-1">
                  <div className="text-sm font-medium">Address</div>
                  <div className="flex items-center gap-2">
                    <Globe className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-mono">{proxyConfig.bind_address}</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-medium">Port</div>
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-mono">{proxyConfig.port}</span>
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-medium">Protocol</div>
                  <div className="flex items-center gap-2">
                    {proxyConfig.enable_tls ? (
                      <>
                        <Lock className="h-4 w-4 text-green-500" />
                        <span className="text-sm text-green-700 dark:text-green-400">HTTPS</span>
                        <Badge variant="outline" className="text-xs">
                          {proxyConfig.tls_mode === 'self_signed' ? 'Self-signed' : 'Custom'}
                        </Badge>
                      </>
                    ) : (
                      <>
                        <Globe className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm text-gray-600 dark:text-gray-300">HTTP</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-medium">Status</div>
                  <div className="flex items-center gap-2">
                    {proxyRunning ? (
                      <>
                        <CheckCircle className="h-4 w-4 text-green-500" />
                        <span className="text-sm text-green-700 dark:text-green-400">Active</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-4 w-4 text-gray-400" />
                        <span className="text-sm text-gray-500">Inactive</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-medium">Actions</div>
                  <div className="flex gap-2">
                    {!proxyRunning ? (
                      <Button
                        size="sm"
                        onClick={handleStartServer}
                        disabled={startServerMutation.isPending || !hasValidAuth}
                        className="flex items-center gap-2"
                      >
                        <Play className="h-3 w-3" />
                        {startServerMutation.isPending ? 'Starting...' : 'Start'}
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={handleStopServer}
                        disabled={stopServerMutation.isPending}
                        className="flex items-center gap-2"
                      >
                        <Square className="h-3 w-3" />
                        {stopServerMutation.isPending ? 'Stopping...' : 'Stop'}
                      </Button>
                    )}
                    {proxyRunning && proxyConfig && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(getServerUrl())}
                        className="flex items-center gap-1"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Connection Details Card */}
        {proxyRunning && proxyConfig && (
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Zap className="h-4 w-4" />
                Connection Details
              </CardTitle>
              <CardDescription>
                Use these details to configure your API clients
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium">Base URL</label>
                    <div className="flex items-center gap-2 mt-1">
                      <code className="flex-1 px-3 py-2 bg-muted rounded-md text-sm font-mono">
                        {getServerUrl()}
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(getServerUrl())}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium">API Key</label>
                    <div className="flex items-center gap-2 mt-1">
                      <code className="flex-1 px-3 py-2 bg-muted rounded-md text-sm">
                        Any non-empty string (e.g., "dummy")
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard('dummy')}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium">Messages Endpoint</label>
                    <div className="flex items-center gap-2 mt-1">
                      <code className="flex-1 px-3 py-2 bg-muted rounded-md text-sm font-mono">
                        /v1/messages
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard(`${getServerUrl()}/v1/messages`)}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium">Model</label>
                    <div className="flex items-center gap-2 mt-1">
                      <code className="flex-1 px-3 py-2 bg-muted rounded-md text-sm">
                        claude-sonnet-4-20250514
                      </code>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => copyToClipboard('claude-sonnet-4-20250514')}
                      >
                        <Copy className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
              <div className="bg-blue-50 dark:bg-blue-950 rounded-lg p-3 border border-blue-200 dark:border-blue-800">
                <h4 className="font-medium text-gray-900 dark:text-blue-50 mb-2 flex items-center gap-2">
                  <Info className="h-4 w-4 text-blue-500 dark:text-blue-400" />
                  Quick Setup
                </h4>
                <div className="space-y-1 text-sm text-gray-900 dark:text-blue-50">
                  <div><strong>Base URL:</strong> <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded text-gray-900 dark:text-blue-50">{getServerUrl()}</code></div>
                  <div><strong>API Key:</strong> <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded text-gray-900 dark:text-blue-50">dummy</code></div>
                  <div><strong>Model:</strong> <code className="bg-blue-100 dark:bg-blue-900 px-1 rounded text-gray-900 dark:text-blue-50">claude-sonnet-4-20250514</code></div>
                </div>
              </div>
              {proxyConfig.enable_tls && (
                <div className="bg-green-50 dark:bg-green-950 rounded-lg p-3 border border-green-200 dark:border-green-800">
                  <h4 className="font-medium text-gray-900 dark:text-green-50 mb-2 flex items-center gap-2">
                    <Lock className="h-4 w-4 text-green-500 dark:text-green-400" />
                    TLS Certificate Details
                  </h4>
                  <div className="space-y-1 text-sm text-gray-900 dark:text-green-50">
                    <div>
                      <strong>Mode:</strong>{' '}
                      {proxyConfig.tls_mode === 'self_signed' ? 'Self-signed' : 'Custom'}
                    </div>
                    {proxyConfig.tls_cert_path && (
                      <div>
                        <strong>Certificate:</strong>{' '}
                        <code className="bg-green-100 dark:bg-green-900 px-1 rounded text-gray-900 dark:text-green-50">
                          {proxyConfig.tls_cert_path}
                        </code>
                      </div>
                    )}
                    {proxyConfig.tls_mode === 'custom' && proxyConfig.tls_key_path && (
                      <div>
                        <strong>Key:</strong>{' '}
                        <code className="bg-green-100 dark:bg-green-900 px-1 rounded text-gray-900 dark:text-green-50">
                          {proxyConfig.tls_key_path}
                        </code>
                      </div>
                    )}
                    {proxyConfig.tls_mode === 'self_signed' && (
                      <div className="text-xs text-gray-700 dark:text-green-200">
                        Trust this certificate on your client to avoid HTTPS warnings.
                      </div>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Important Notes Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
            Important Notes
          </CardTitle>
          <CardDescription>
            Please read these important considerations before using the proxy
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="p-3 bg-amber-50 dark:bg-amber-950 rounded-lg border border-amber-200 dark:border-amber-800">
            <ul className="text-sm text-gray-900 dark:text-amber-50 space-y-1">
              <li>• This proxy uses unofficial OAuth flows and may stop working without notice</li>
              <li>• Requires an active Claude Pro or Claude Max subscription</li>
              <li>• Usage is subject to Anthropic's terms of service</li>
              <li>• Keep your authentication tokens secure</li>
              {proxyConfig?.enable_tls && proxyConfig.tls_cert_path && (
                <li>
                  • HTTPS is enabled — trust the certificate at{' '}
                  <code className="bg-amber-100 dark:bg-amber-900 px-1 rounded text-gray-900 dark:text-amber-50">
                    {proxyConfig.tls_cert_path}
                  </code>{' '}
                  on any client that validates TLS.
                </li>
              )}
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ProxyPage;

import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  Server,
  Save,
  RotateCcw,
  AlertTriangle,
  CheckCircle,
  Info,
  Globe,
  Shield,
  Zap
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { useAppContext } from '@/contexts/AppContext';
import { getProxyConfig, updateProxyConfig, getProxyStatus } from '@/lib/api';
import { ProxyConfig } from '@/types';

const configSchema = z.object({
  port: z.number().int().min(1).max(65535),
  bind_address: z.string().min(1),
  debug_mode: z.boolean(),
  openai_compatible: z.boolean(),
});

type ConfigFormData = z.infer<typeof configSchema>;

const SettingsPage: React.FC = () => {
  const { state, refreshAppState } = useAppContext();
  const [message, setMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isDirty },
    watch,
  } = useForm<ConfigFormData>({
    resolver: zodResolver(configSchema),
    defaultValues: {
      port: 8081,
      bind_address: '0.0.0.0',
      debug_mode: false,
      openai_compatible: false,
    },
  });

  // Queries
  const { data: configData, refetch: refetchConfig } = useQuery({
    queryKey: ['proxyConfig'],
    queryFn: getProxyConfig,
  });

  const { data: statusData } = useQuery({
    queryKey: ['proxyStatus'],
    queryFn: getProxyStatus,
  });

  // Mutations
  const updateConfigMutation = useMutation({
    mutationFn: (config: ProxyConfig) => updateProxyConfig(config),
    onSuccess: (result) => {
      if (result.success) {
        setMessage({ type: 'success', text: 'Configuration updated successfully!' });
        refetchConfig();
        refreshAppState();
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to update configuration' });
      }
    },
  });

  const currentConfig = configData?.data ?? state.proxyConfig;
  const serverRunning = statusData?.data ?? state.proxyRunning;

  // Update form when config data is loaded
  useEffect(() => {
    if (currentConfig) {
      reset({
        port: currentConfig.port,
        bind_address: currentConfig.bind_address,
        debug_mode: currentConfig.debug_mode,
        openai_compatible: currentConfig.openai_compatible,
      });
    }
  }, [currentConfig, reset]);

  const onSubmit = (data: ConfigFormData) => {
    setMessage(null);
    updateConfigMutation.mutate(data);
  };

  const handleReset = () => {
    if (currentConfig) {
      reset({
        port: currentConfig.port,
        bind_address: currentConfig.bind_address,
        debug_mode: currentConfig.debug_mode,
        openai_compatible: currentConfig.openai_compatible,
      });
      setMessage(null);
    }
  };

  const watchedValues = watch();

  return (
    <div className="max-w-full mx-auto space-y-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">
          Configure your proxy server and application preferences.
        </p>
      </div>

      {/* Status Alert */}
      {message && (
        <Alert variant={message.type === 'error' ? 'destructive' : message.type === 'success' ? 'success' : 'default'}>
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
      )}

      {/* Server Running Warning */}
      {serverRunning && (
        <Alert variant="warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            The proxy server is currently running. Configuration changes will take effect after restarting the server.
          </AlertDescription>
        </Alert>
      )}

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Server Configuration Card */}
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Server className="h-4 w-4" />
                Server Configuration
              </CardTitle>
              <CardDescription>
                Basic server settings for the proxy
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="port">Port</Label>
                  <Input
                    id="port"
                    type="number"
                    min="1"
                    max="65535"
                    {...register('port', { valueAsNumber: true })}
                    className={errors.port ? 'border-red-500' : ''}
                  />
                  {errors.port && (
                    <p className="text-sm text-red-600 dark:text-red-400">
                      {errors.port.message}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    Port number for the proxy server (1-65535)
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="bind_address">Bind Address</Label>
                  <Input
                    id="bind_address"
                    {...register('bind_address')}
                    placeholder="0.0.0.0"
                    className={errors.bind_address ? 'border-red-500' : ''}
                  />
                  {errors.bind_address && (
                    <p className="text-sm text-red-600 dark:text-red-400">
                      {errors.bind_address.message}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    IP address to bind to (0.0.0.0 for all interfaces)
                  </p>
                </div>

              <div className="bg-blue-50 dark:bg-blue-950 rounded-lg p-3 border border-blue-200 dark:border-blue-800">
                <h4 className="font-medium text-gray-900 dark:text-blue-50 mb-1 flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-500 dark:text-blue-400" />
                  Current Server URL
                </h4>
                <code className="block bg-blue-100 dark:bg-blue-900 px-2 py-1 rounded text-sm font-mono text-gray-900 dark:text-blue-50">
                  http://{watchedValues.bind_address}:{watchedValues.port}
                </code>
              </div>
            </CardContent>
          </Card>

          {/* Features Configuration Card */}
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Zap className="h-4 w-4" />
                Features & Compatibility
              </CardTitle>
              <CardDescription>
                Enable or disable specific proxy features
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <Label htmlFor="debug_mode">Debug Mode</Label>
                    <Badge variant="secondary" className="text-xs">Development</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">
                    Enable detailed logging for debugging and development
                  </p>
                </div>
                <input
                  id="debug_mode"
                  type="checkbox"
                  {...register('debug_mode')}
                  className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
              </div>

                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Label htmlFor="openai_compatible">OpenAI Compatible API</Label>
                      <Badge variant="warning" className="text-xs">Beta</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      Enable OpenAI-compatible endpoints for broader client support
                    </p>
                  </div>
                  <input
                    id="openai_compatible"
                    type="checkbox"
                    {...register('openai_compatible')}
                    className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </div>
                {watchedValues.openai_compatible && (
                  <Alert className="mt-3">
                    <Info className="h-4 w-4" />
                    <AlertDescription>
                      OpenAI compatibility mode will enable additional endpoints like <code>/v1/chat/completions</code> that translate requests to Anthropic's format.
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Security Information Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-4 w-4" />
              Security Information
            </CardTitle>
            <CardDescription>
              Important security considerations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="flex items-start gap-2 p-3 bg-amber-50 dark:bg-amber-950 rounded-lg border border-amber-200 dark:border-amber-800">
                <AlertTriangle className="h-4 w-4 text-amber-500 dark:text-amber-400 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-amber-50">Network Exposure</p>
                  <p className="text-xs text-gray-700 dark:text-amber-200 mt-1">
                    Binding to 0.0.0.0 exposes server to all interfaces. Use 127.0.0.1 for local-only.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-2 p-3 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
                <CheckCircle className="h-4 w-4 text-green-500 dark:text-green-400 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-green-50">Token Security</p>
                  <p className="text-xs text-gray-700 dark:text-green-200 mt-1">
                    Tokens stored securely and never exposed in logs.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-2 p-3 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
                <Info className="h-4 w-4 text-blue-500 dark:text-blue-400 mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-blue-50">API Key</p>
                  <p className="text-xs text-gray-700 dark:text-blue-200 mt-1">
                    Any non-empty API key works - authentication handled via OAuth.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-2 pt-2">
          <Button
            type="submit"
            size="sm"
            disabled={!isDirty || updateConfigMutation.isPending}
            className="flex items-center gap-2"
          >
            <Save className="h-4 w-4" />
            {updateConfigMutation.isPending ? 'Saving...' : 'Save Changes'}
          </Button>

          {isDirty && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleReset}
              className="flex items-center gap-2"
            >
              <RotateCcw className="h-4 w-4" />
              Reset
            </Button>
          )}
        </div>
      </form>
    </div>
  );
};

export default SettingsPage;

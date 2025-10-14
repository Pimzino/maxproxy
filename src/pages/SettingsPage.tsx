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
  Zap,
  Monitor,
  PlayCircle,
  Power,
  Lock,
  Key
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { useAppContext } from '@/contexts/AppContext';
import { getProxyConfig, updateProxyConfig, getProxyStatus, getSystemInfo } from '@/lib/api';
import { ProxyConfig, SystemInfo } from '@/types';
import { open } from '@tauri-apps/plugin-dialog';

const configSchema = z
  .object({
    port: z.number().int().min(1).max(65535),
    bind_address: z.string().min(1),
    debug_mode: z.boolean(),
    openai_compatible: z.boolean(),
    start_minimized: z.boolean(),
    auto_start_proxy: z.boolean(),
    launch_on_startup: z.boolean(),
    enable_tls: z.boolean(),
    tls_mode: z.enum(['self_signed', 'custom']),
    tls_cert_path: z.string().optional().nullable(),
    tls_key_path: z.string().optional().nullable(),
  })
  .superRefine((data, ctx) => {
    if (data.enable_tls && data.tls_mode === 'custom') {
      if (!data.tls_cert_path || data.tls_cert_path.trim() === '') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Certificate path is required when using custom TLS.',
          path: ['tls_cert_path'],
        });
      }
      if (!data.tls_key_path || data.tls_key_path.trim() === '') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'Private key path is required when using custom TLS.',
          path: ['tls_key_path'],
        });
      }
    }
  });

type ConfigFormData = z.infer<typeof configSchema>;

const SettingsPage: React.FC = () => {
  const { state, refreshAppState } = useAppContext();
  const [message, setMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [launchLabel, setLaunchLabel] = useState('Launch on Startup');
  const [launchDescription, setLaunchDescription] = useState('Add MaxProxy to your operating system\'s startup apps list.');
  const [launchBadge, setLaunchBadge] = useState('Startup');

  const {
    register,
    handleSubmit,
    reset,
    setValue,
    trigger,
    formState: { errors, isDirty },
    watch,
  } = useForm<ConfigFormData>({
    resolver: zodResolver(configSchema),
    defaultValues: {
      port: 8081,
      bind_address: '0.0.0.0',
      debug_mode: false,
      openai_compatible: false,
      start_minimized: false,
      auto_start_proxy: false,
      launch_on_startup: false,
      enable_tls: false,
      tls_mode: 'self_signed',
      tls_cert_path: '',
      tls_key_path: '',
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

  useEffect(() => {
    (async () => {
      try {
        const res = await getSystemInfo();
        if (!res.success || !res.data) return;
        const sys: SystemInfo = res.data;
        const os = sys.os.toLowerCase();
        if (os.includes('windows')) {
          setLaunchLabel('Launch with Windows');
          setLaunchDescription('Add MaxProxy to the Windows startup apps list.');
          setLaunchBadge('Windows');
        } else if (os.includes('mac')) {
          setLaunchLabel('Launch at Login');
          setLaunchDescription('Open MaxProxy automatically when you sign in to macOS.');
          setLaunchBadge('Login Item');
        } else if (os.includes('linux')) {
          setLaunchLabel('Launch on Startup');
          setLaunchDescription('Start MaxProxy alongside your desktop session.');
          setLaunchBadge('Startup');
        } else {
          setLaunchLabel('Launch on Startup');
          setLaunchDescription('Start MaxProxy automatically with your device.');
          setLaunchBadge('Startup');
        }
      } catch {
        // retain defaults
      }
    })();
  }, []);

  // Update form when config data is loaded
  useEffect(() => {
    if (currentConfig) {
      reset({
        port: currentConfig.port,
        bind_address: currentConfig.bind_address,
        debug_mode: currentConfig.debug_mode,
        openai_compatible: currentConfig.openai_compatible,
        start_minimized: currentConfig.start_minimized,
        auto_start_proxy: currentConfig.auto_start_proxy,
        launch_on_startup: currentConfig.launch_on_startup,
        enable_tls: currentConfig.enable_tls ?? false,
        tls_mode: currentConfig.tls_mode ?? 'self_signed',
        tls_cert_path: currentConfig.tls_cert_path ?? '',
        tls_key_path: currentConfig.tls_key_path ?? '',
      });
    }
  }, [currentConfig, reset]);

  const onSubmit = (data: ConfigFormData) => {
    setMessage(null);
    const trimmedCert = data.tls_cert_path?.trim() ?? '';
    const trimmedKey = data.tls_key_path?.trim() ?? '';
    const payload: ProxyConfig = {
      ...data,
      tls_cert_path:
        data.enable_tls && data.tls_mode === 'custom' && trimmedCert
          ? trimmedCert
          : undefined,
      tls_key_path:
        data.enable_tls && data.tls_mode === 'custom' && trimmedKey
          ? trimmedKey
          : undefined,
    };

    if (data.tls_mode === 'self_signed') {
      payload.tls_cert_path = undefined;
      payload.tls_key_path = undefined;
    }

    updateConfigMutation.mutate(payload);
  };

  const handleReset = () => {
    if (currentConfig) {
      reset({
        port: currentConfig.port,
        bind_address: currentConfig.bind_address,
        debug_mode: currentConfig.debug_mode,
        openai_compatible: currentConfig.openai_compatible,
        start_minimized: currentConfig.start_minimized,
        auto_start_proxy: currentConfig.auto_start_proxy,
        launch_on_startup: currentConfig.launch_on_startup,
        enable_tls: currentConfig.enable_tls ?? false,
        tls_mode: currentConfig.tls_mode ?? 'self_signed',
        tls_cert_path: currentConfig.tls_cert_path ?? '',
        tls_key_path: currentConfig.tls_key_path ?? '',
      });
      setMessage(null);
    }
  };

  const watchedValues = watch();
  const currentScheme = watchedValues.enable_tls ? 'https' : 'http';
  const isTlsEnabled = watchedValues.enable_tls;
  const isCustomTls = isTlsEnabled && watchedValues.tls_mode === 'custom';
  const selfSignedCertPath =
    currentConfig?.tls_cert_path ??
    (typeof watchedValues.tls_cert_path === 'string'
      ? watchedValues.tls_cert_path
      : '');
  const selfSignedKeyPath =
    currentConfig?.tls_key_path ??
    (typeof watchedValues.tls_key_path === 'string'
      ? watchedValues.tls_key_path
      : '');

  const handleBrowseCert = async () => {
    if (!isCustomTls) return;
    const selected = await open({
      multiple: false,
      filters: [
        {
          name: 'Certificate',
          extensions: ['pem', 'crt', 'cer'],
        },
      ],
    });

    if (typeof selected === 'string') {
      setValue('tls_cert_path', selected);
      trigger('tls_cert_path');
    }
  };

  const handleBrowseKey = async () => {
    if (!isCustomTls) return;
    const selected = await open({
      multiple: false,
      filters: [
        {
          name: 'Private Key',
          extensions: ['pem', 'key'],
        },
      ],
    });

    if (typeof selected === 'string') {
      setValue('tls_key_path', selected);
      trigger('tls_key_path');
    }
  };

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
                  {isTlsEnabled ? (
                    <Badge variant="success" className="text-xs">
                      HTTPS
                    </Badge>
                  ) : (
                    <Badge variant="secondary" className="text-xs">
                      HTTP
                    </Badge>
                  )}
                </h4>
                <code className="block bg-blue-100 dark:bg-blue-900 px-2 py-1 rounded text-sm font-mono text-gray-900 dark:text-blue-50">
                  {currentScheme}://{watchedValues.bind_address}:{watchedValues.port}
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

          {/* TLS Configuration Card */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Lock className="h-4 w-4" />
                TLS & Encryption
              </CardTitle>
              <CardDescription>
                Serve the proxy over HTTPS with a self-signed or custom certificate
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-3 border rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <Label htmlFor="enable_tls">Enable TLS</Label>
                    <Badge variant={isTlsEnabled ? 'success' : 'secondary'} className="text-xs">
                      {isTlsEnabled ? 'Active' : 'Disabled'}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">
                    Terminate HTTPS connections at MaxProxy to protect API traffic on the network.
                  </p>
                </div>
                <input
                  id="enable_tls"
                  type="checkbox"
                  {...register('enable_tls')}
                  className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label htmlFor="tls_mode">TLS Mode</Label>
                  <select
                    id="tls_mode"
                    {...register('tls_mode')}
                    disabled={!isTlsEnabled}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  >
                    <option value="self_signed">Generate self-signed certificate</option>
                    <option value="custom">Use custom certificate &amp; key</option>
                  </select>
                  <p className="text-xs text-muted-foreground">
                    Self-signed certificates are stored in your MaxProxy data directory.
                  </p>
                </div>
              </div>

              {isTlsEnabled && watchedValues.tls_mode === 'self_signed' && (
                <div className="bg-green-50 dark:bg-green-950 rounded-lg p-3 border border-green-200 dark:border-green-800">
                  <h4 className="font-medium text-gray-900 dark:text-green-50 mb-1 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-green-500 dark:text-green-400" />
                    Self-Signed Certificate
                  </h4>
                  <p className="text-xs text-gray-700 dark:text-green-100">
                    A certificate/key pair will be generated automatically if it does not exist. Trust this certificate on any client that needs to verify HTTPS.
                  </p>
                  {(selfSignedCertPath || selfSignedKeyPath) && (
                    <div className="mt-2 text-xs text-gray-700 dark:text-green-100 space-y-1">
                      {selfSignedCertPath && (
                        <div>
                          <span className="font-medium">Certificate:</span>{' '}
                          <code className="bg-green-100 dark:bg-green-900 px-1 rounded text-gray-900 dark:text-green-50">
                            {selfSignedCertPath}
                          </code>
                        </div>
                      )}
                      {selfSignedKeyPath && (
                        <div>
                          <span className="font-medium">Private Key:</span>{' '}
                          <code className="bg-green-100 dark:bg-green-900 px-1 rounded text-gray-900 dark:text-green-50">
                            {selfSignedKeyPath}
                          </code>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {isCustomTls && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="space-y-2">
                    <Label htmlFor="tls_cert_path" className="flex items-center gap-2">
                      <Shield className="h-3 w-3" />
                      Certificate File (.pem)
                    </Label>
                    <div className="flex items-center gap-2">
                      <Input
                        id="tls_cert_path"
                        {...register('tls_cert_path')}
                        disabled={!isCustomTls}
                        placeholder="/path/to/certificate.pem"
                        className={errors.tls_cert_path ? 'border-red-500' : ''}
                      />
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={handleBrowseCert}
                        disabled={!isCustomTls}
                        className="flex items-center gap-1"
                      >
                        Browse
                      </Button>
                    </div>
                    {errors.tls_cert_path && (
                      <p className="text-sm text-red-600 dark:text-red-400">
                        {errors.tls_cert_path.message}
                      </p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Provide the PEM-encoded server certificate chain.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="tls_key_path" className="flex items-center gap-2">
                      <Key className="h-3 w-3" />
                      Private Key File (.pem/.key)
                    </Label>
                    <div className="flex items-center gap-2">
                      <Input
                        id="tls_key_path"
                        {...register('tls_key_path')}
                        disabled={!isCustomTls}
                        placeholder="/path/to/private.key"
                        className={errors.tls_key_path ? 'border-red-500' : ''}
                      />
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={handleBrowseKey}
                        disabled={!isCustomTls}
                        className="flex items-center gap-1"
                      >
                        Browse
                      </Button>
                    </div>
                    {errors.tls_key_path && (
                      <p className="text-sm text-red-600 dark:text-red-400">
                        {errors.tls_key_path.message}
                      </p>
                    )}
                    <p className="text-xs text-muted-foreground">
                      Must match the certificate&apos;s private key (PEM, PKCS#8, or RSA).
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Application Preferences Card */}
          <Card className="lg:col-span-1">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-lg">
                <Monitor className="h-4 w-4" />
                Application Preferences
              </CardTitle>
              <CardDescription>
                Control how MaxProxy behaves when it launches
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Label htmlFor="start_minimized">Start Minimized</Label>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      Keep the window hidden and accessible from the tray when the app first opens.
                    </p>
                  </div>
                  <input
                    id="start_minimized"
                    type="checkbox"
                    {...register('start_minimized')}
                    className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </div>

                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Label htmlFor="auto_start_proxy">Start Proxy on Launch</Label>
                      <Badge variant="outline" className="text-xs">Convenience</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      Automatically run the proxy service when MaxProxy starts.
                    </p>
                  </div>
                  <input
                    id="auto_start_proxy"
                    type="checkbox"
                    {...register('auto_start_proxy')}
                    className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </div>

                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Label htmlFor="launch_on_startup">{launchLabel}</Label>
                      <Badge variant="secondary" className="text-xs flex items-center gap-1">
                        <Power className="h-3 w-3" />
                        {launchBadge}
                      </Badge>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {launchDescription}
                    </p>
                  </div>
                  <input
                    id="launch_on_startup"
                    type="checkbox"
                    {...register('launch_on_startup')}
                    className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                  />
                </div>
              </div>

              {watchedValues.auto_start_proxy && !serverRunning && (
                <Alert className="mt-3">
                  <PlayCircle className="h-4 w-4" />
                  <AlertDescription>
                    The proxy will start automatically the next time the app launches. You can also start it now from the tray menu.
                  </AlertDescription>
                </Alert>
              )}
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

import React, { useState, useEffect } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  Shield,
  CheckCircle,
  XCircle,
  Clock,
  ExternalLink,
  Trash2,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useAppContext } from '@/contexts/AppContext';
import {
  startOAuthFlow,
  exchangeOAuthCode,
  refreshToken,
  clearTokens,
  getTokenStatus
} from '@/lib/api';

const AuthPage: React.FC = () => {
  const { state, refreshAppState } = useAppContext();
  const [authCode, setAuthCode] = useState('');
  const [isDarkMode, setIsDarkMode] = useState(false);

  // Detect dark mode changes
  useEffect(() => {
    const checkDarkMode = () => {
      setIsDarkMode(document.documentElement.classList.contains('dark'));
    };

    // Check initially
    checkDarkMode();

    // Create observer to watch for dark mode changes
    const observer = new MutationObserver(checkDarkMode);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class']
    });

    return () => observer.disconnect();
  }, []);
  const [message, setMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  // Query for token status
  const { data: tokenStatusData, refetch: refetchTokenStatus } = useQuery({
    queryKey: ['tokenStatus'],
    queryFn: getTokenStatus,
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  // Mutations
  const startAuthMutation = useMutation({
    mutationFn: startOAuthFlow,
    onSuccess: (result) => {
      if (result.success && result.data) {
        setMessage({ type: 'info', text: 'OAuth flow started! Please complete the login in your browser.' });
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to start OAuth flow' });
      }
    },
  });

  const exchangeCodeMutation = useMutation({
    mutationFn: exchangeOAuthCode,
    onSuccess: (result) => {
      if (result.success) {
        setMessage({ type: 'success', text: 'Authentication successful! Tokens have been saved.' });
        setAuthCode('');
        refetchTokenStatus();
        refreshAppState();
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to exchange authorization code' });
      }
    },
  });

  const refreshTokenMutation = useMutation({
    mutationFn: refreshToken,
    onSuccess: (result) => {
      if (result.success) {
        setMessage({ type: 'success', text: 'Tokens refreshed successfully!' });
        refetchTokenStatus();
        refreshAppState();
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to refresh tokens' });
      }
    },
  });

  const clearTokensMutation = useMutation({
    mutationFn: clearTokens,
    onSuccess: (result) => {
      if (result.success) {
        setMessage({ type: 'success', text: 'Tokens cleared successfully!' });
        refetchTokenStatus();
        refreshAppState();
      } else {
        setMessage({ type: 'error', text: result.error || 'Failed to clear tokens' });
      }
    },
  });

  const tokenStatus = tokenStatusData?.data || state.tokenStatus;
  const hasValidTokens = tokenStatus?.has_tokens && !tokenStatus?.is_expired;

  const handleStartAuth = () => {
    setMessage(null);
    startAuthMutation.mutate();
  };

  const handleExchangeCode = () => {
    if (!authCode.trim()) {
      setMessage({ type: 'error', text: 'Please enter the authorization code' });
      return;
    }
    setMessage(null);
    exchangeCodeMutation.mutate(authCode.trim());
  };

  const handleRefreshTokens = () => {
    setMessage(null);
    refreshTokenMutation.mutate();
  };

  const handleClearTokens = () => {
    if (confirm('Are you sure you want to clear all stored tokens? You will need to authenticate again.')) {
      setMessage(null);
      clearTokensMutation.mutate();
    }
  };


  const getStatusIcon = () => {
    if (!tokenStatus?.has_tokens) {
      return <XCircle className="h-5 w-5 text-red-500" />;
    }
    if (tokenStatus.is_expired) {
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
    }
    return <CheckCircle className="h-5 w-5 text-green-500" />;
  };

  const getStatusBadge = () => {
    if (!tokenStatus?.has_tokens) {
      return <Badge variant="destructive">No Authentication</Badge>;
    }
    if (tokenStatus.is_expired) {
      return <Badge variant="warning">Expired</Badge>;
    }
    return <Badge variant="success">Authenticated</Badge>;
  };

  return (
    <div className="max-w-6xl mx-auto space-y-4">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">Authentication</h1>
        <p className="text-muted-foreground">
          Manage your OAuth tokens and authentication with Anthropic's API.
        </p>
      </div>

      {/* Status Alert */}
      {message && (
        <Alert variant={message.type === 'error' ? 'destructive' : message.type === 'success' ? 'success' : 'default'}>
          <AlertDescription>{message.text}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Token Status Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {getStatusIcon()}
                <div>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    Authentication Status
                    {getStatusBadge()}
                  </CardTitle>
                  <CardDescription>
                    Current OAuth token status and validity
                  </CardDescription>
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {tokenStatus && (
              <div className="grid grid-cols-1 gap-3">
                <div className="space-y-1">
                  <div className="text-sm font-medium">Token Status</div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon()}
                    <span className="text-sm">
                      {!tokenStatus.has_tokens
                        ? 'No tokens available'
                        : tokenStatus.is_expired
                        ? 'Tokens expired'
                        : 'Tokens valid'}
                    </span>
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-medium">Time Until Expiry</div>
                  <div className="flex items-center gap-2">
                    <Clock className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">{tokenStatus.time_until_expiry}</span>
                  </div>
                </div>
              </div>
            )}
            <div className="flex flex-wrap gap-2 pt-2">
              {hasValidTokens && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleRefreshTokens}
                  disabled={refreshTokenMutation.isPending}
                >
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh Tokens
                </Button>
              )}
              {tokenStatus?.has_tokens && (
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleClearTokens}
                  disabled={clearTokensMutation.isPending}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Clear Tokens
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* OAuth Flow Card */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              <Shield className="h-4 w-4" />
              OAuth Authentication
            </CardTitle>
            <CardDescription>
              Authenticate with Anthropic using OAuth to access the API.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {!hasValidTokens && (
              <>
                <div>
                  <h3 className="text-base font-medium mb-2">Step 1: Start OAuth Flow</h3>
                  <p className="text-sm text-muted-foreground mb-3">
                    Click the button below to open the authentication page.
                  </p>
                  <Button
                    onClick={handleStartAuth}
                    disabled={startAuthMutation.isPending}
                    size="sm"
                  >
                    <ExternalLink className="h-4 w-4 mr-2" />
                    {startAuthMutation.isPending ? 'Opening...' : 'Start OAuth Login'}
                  </Button>
                </div>
                <div className="border-t pt-4">
                  <h3 className="text-base font-medium mb-2">Step 2: Enter Authorization Code</h3>
                  <p className="text-sm text-muted-foreground mb-3">
                    After completing OAuth, paste the authorization code below.
                  </p>
                  <div className="flex gap-2">
                    <Input
                      placeholder="Enter authorization code..."
                      value={authCode}
                      onChange={(e) => setAuthCode(e.target.value)}
                      className="flex-1"
                    />
                    <Button
                      onClick={handleExchangeCode}
                      disabled={exchangeCodeMutation.isPending || !authCode.trim()}
                      size="sm"
                    >
                      {exchangeCodeMutation.isPending ? 'Processing...' : 'Authenticate'}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground mt-2">
                    Format: code#state
                  </p>
                </div>
              </>
            )}

            {hasValidTokens && (
              <Alert variant="success">
                <CheckCircle className="h-4 w-4" />
                <AlertDescription>
                  Successfully authenticated! Tokens valid for {tokenStatus?.time_until_expiry}.
                </AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Instructions Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Authentication Instructions</CardTitle>
          <CardDescription>
            How to use the OAuth authentication system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="flex gap-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400 rounded-full flex items-center justify-center text-sm font-medium">
                1
              </div>
              <div>
                <p className="font-medium">Prerequisites</p>
                <p className="text-sm text-muted-foreground">
                  Active Claude Pro/Max subscription required.
                </p>
              </div>
            </div>
            <div className="flex gap-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400 rounded-full flex items-center justify-center text-sm font-medium">
                2
              </div>
              <div>
                <p className="font-medium">Start OAuth Flow</p>
                <p className="text-sm text-muted-foreground">
                  Click "Start OAuth Login" to open authentication.
                </p>
              </div>
            </div>
            <div className="flex gap-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400 rounded-full flex items-center justify-center text-sm font-medium">
                3
              </div>
              <div>
                <p className="font-medium">Complete Login</p>
                <p className="text-sm text-muted-foreground">
                  Sign in and authorize the application.
                </p>
              </div>
            </div>
            <div className="flex gap-3">
              <div className="flex-shrink-0 w-6 h-6 bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400 rounded-full flex items-center justify-center text-sm font-medium">
                4
              </div>
              <div>
                <p className="font-medium">Copy Code</p>
                <p className="text-sm text-muted-foreground">
                  Copy authorization code from callback URL.
                </p>
              </div>
            </div>
          </div>

          <div className="p-3 bg-amber-50 dark:bg-amber-950 rounded-lg border border-amber-200 dark:border-amber-800 mt-4">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-500 dark:text-amber-400 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-amber-50">Important Notes</p>
                <ul className="text-sm mt-1 space-y-1 text-gray-700 dark:text-amber-200">
                  <li>• This proxy uses unofficial OAuth flows and may stop working without notice</li>
                  <li>• Requires an active Claude Pro or Claude Max subscription</li>
                  <li>• Usage is subject to Anthropic's terms of service</li>
                  <li>• Keep your authentication tokens secure</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default AuthPage;
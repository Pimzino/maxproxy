import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { AppState, TokenStatus, ProxyConfig, LogEntry, InitStatus } from '@/types';
import { getTokenStatus, getProxyStatus, getProxyConfig, getInitStatus } from '@/lib/api';

interface AppContextType {
  state: AppState;
  isInitialized: boolean;
  updateTokenStatus: (status: TokenStatus) => void;
  updateProxyConfig: (config: ProxyConfig) => void;
  updateProxyRunning: (running: boolean) => void;
  updateLogs: (logs: LogEntry[]) => void;
  updateInitStatus: (status: InitStatus) => void;
  refreshAppState: () => Promise<void>;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

type AppAction =
  | { type: 'UPDATE_TOKEN_STATUS'; payload: TokenStatus }
  | { type: 'UPDATE_PROXY_CONFIG'; payload: ProxyConfig }
  | { type: 'UPDATE_PROXY_RUNNING'; payload: boolean }
  | { type: 'UPDATE_LOGS'; payload: LogEntry[] }
  | { type: 'UPDATE_INIT_STATUS'; payload: InitStatus };

const initialState: AppState = {
  tokenStatus: null,
  proxyConfig: null,
  proxyRunning: false,
  logs: [],
  initStatus: null,
};

const appReducer = (state: AppState, action: AppAction): AppState => {
  switch (action.type) {
    case 'UPDATE_TOKEN_STATUS':
      return { ...state, tokenStatus: action.payload };
    case 'UPDATE_PROXY_CONFIG':
      return { ...state, proxyConfig: action.payload };
    case 'UPDATE_PROXY_RUNNING':
      return { ...state, proxyRunning: action.payload };
    case 'UPDATE_LOGS':
      return { ...state, logs: action.payload };
    case 'UPDATE_INIT_STATUS':
      return { ...state, initStatus: action.payload };
    default:
      return state;
  }
};

interface AppProviderProps {
  children: React.ReactNode;
}

export const AppProvider: React.FC<AppProviderProps> = ({ children }) => {
  const [state, dispatch] = useReducer(appReducer, initialState);
  const [isInitialized, setIsInitialized] = React.useState(false);

  const updateTokenStatus = (status: TokenStatus) => {
    dispatch({ type: 'UPDATE_TOKEN_STATUS', payload: status });
  };

  const updateProxyConfig = (config: ProxyConfig) => {
    dispatch({ type: 'UPDATE_PROXY_CONFIG', payload: config });
  };

  const updateProxyRunning = (running: boolean) => {
    dispatch({ type: 'UPDATE_PROXY_RUNNING', payload: running });
  };

  const updateLogs = (logs: LogEntry[]) => {
    dispatch({ type: 'UPDATE_LOGS', payload: logs });
  };

  const updateInitStatus = (status: InitStatus) => {
    dispatch({ type: 'UPDATE_INIT_STATUS', payload: status });
  };

  const refreshAppState = async () => {
    try {
      // Load token status
      const tokenResult = await getTokenStatus();
      if (tokenResult.success && tokenResult.data) {
        updateTokenStatus(tokenResult.data);
      }

      // Load proxy status
      const proxyStatusResult = await getProxyStatus();
      if (proxyStatusResult.success && proxyStatusResult.data !== undefined) {
        updateProxyRunning(proxyStatusResult.data);
      }

      // Load proxy config
      const configResult = await getProxyConfig();
      if (configResult.success && configResult.data) {
        updateProxyConfig(configResult.data);
      }
    } catch (error) {
      console.error('Failed to refresh app state:', error);
    }
  };

  const initializeApp = async () => {
    try {
      // First, monitor the initialization status from the backend
      await monitorInitialization();

      // Then load the app state
      await refreshAppState();
    } catch (error) {
      console.error('Failed to initialize app:', error);
    } finally {
      setIsInitialized(true);
    }
  };

  const monitorInitialization = async () => {
    const maxChecks = 30; // Maximum 15 seconds (500ms * 30)
    let checks = 0;

    while (checks < maxChecks) {
      try {
        const initResult = await getInitStatus();
        if (initResult.success && initResult.data) {
          updateInitStatus(initResult.data);

          // If initialization is complete (whether successful or failed), break
          if (initResult.data.initialization_complete) {
            console.log('[AppInit] Backend initialization complete');
            break;
          }
        }

        checks++;

        // Wait 500ms before next check
        await new Promise(resolve => setTimeout(resolve, 500));
      } catch (error) {
        console.error('Failed to get init status:', error);
        checks++;
        await new Promise(resolve => setTimeout(resolve, 500));
      }
    }
  };

  useEffect(() => {
    // Initial load and initialization
    initializeApp();

    // Set up periodic refresh for dynamic data
    const interval = setInterval(async () => {
      const tokenResult = await getTokenStatus();
      if (tokenResult.success && tokenResult.data) {
        updateTokenStatus(tokenResult.data);
      }

      const proxyStatusResult = await getProxyStatus();
      if (proxyStatusResult.success && proxyStatusResult.data !== undefined) {
        updateProxyRunning(proxyStatusResult.data);
      }
    }, 5000); // Refresh every 5 seconds

    return () => clearInterval(interval);
  }, []);

  const contextValue: AppContextType = {
    state,
    isInitialized,
    updateTokenStatus,
    updateProxyConfig,
    updateProxyRunning,
    updateLogs,
    updateInitStatus,
    refreshAppState,
  };

  return (
    <AppContext.Provider value={contextValue}>
      {children}
    </AppContext.Provider>
  );
};

export const useAppContext = (): AppContextType => {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useAppContext must be used within an AppProvider');
  }
  return context;
};
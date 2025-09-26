import { useEffect, useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import Layout from "./components/layout/Layout";
import { AppProvider, useAppContext } from "./contexts/AppContext";
import AuthPage from "./pages/AuthPage";
import ProxyPage from "./pages/ProxyPage";
import SettingsPage from "./pages/SettingsPage";
import AboutPage from "./pages/AboutPage";
import LogsPage from "./pages/LogsPage";
import "./App.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
    },
  },
});

function AppContent() {
  const [darkMode, setDarkMode] = useState(() => {
    const savedDarkMode = localStorage.getItem('darkMode');
    return savedDarkMode ? JSON.parse(savedDarkMode) : false;
  });
  const { state, isInitialized } = useAppContext();

  useEffect(() => {
    // Apply dark mode class to document element
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  const toggleDarkMode = () => {
    const newDarkMode = !darkMode;
    setDarkMode(newDarkMode);
    localStorage.setItem('darkMode', JSON.stringify(newDarkMode));
  };

  // Check if user has valid authentication tokens
  const hasValidTokens = state.tokenStatus?.has_tokens && !state.tokenStatus?.is_expired;

  // Show loading screen while initializing
  if (!isInitialized) {
    const getLoadingMessage = () => {
      const initStatus = state.initStatus;

      if (!initStatus) {
        return "Initializing application...";
      }

      if (!initStatus.tokens_checked) {
        return "Checking authentication status...";
      }

      if (initStatus.token_refresh_attempted && !initStatus.initialization_complete) {
        return "Refreshing authentication tokens...";
      }

      if (initStatus.token_refresh_successful) {
        return "Authentication refreshed successfully!";
      }

      if (initStatus.error && initStatus.initialization_complete) {
        return "Authentication refresh failed, redirecting...";
      }

      return "Finalizing initialization...";
    };

    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center max-w-md">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 dark:border-gray-100 mx-auto"></div>
          <p className="mt-4 text-gray-600 dark:text-gray-400 font-medium">
            {getLoadingMessage()}
          </p>

          {state.initStatus?.token_refresh_attempted && !state.initStatus.initialization_complete && (
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-500">
              Please wait while we attempt to refresh your tokens...
            </p>
          )}

          {state.initStatus?.error && (
            <p className="mt-3 text-sm text-red-600 dark:text-red-400">
              {state.initStatus.error}
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <Router>
      <Layout
        darkMode={darkMode}
        onToggleDarkMode={toggleDarkMode}
        proxyRunning={state.proxyRunning}
      >
        <Routes>
          <Route
            path="/"
            element={
              <Navigate
                to={hasValidTokens ? "/proxy" : "/auth"}
                replace
              />
            }
          />
          <Route path="/auth" element={<AuthPage />} />
          <Route path="/proxy" element={<ProxyPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/about" element={<AboutPage />} />
          <Route path="/logs" element={<LogsPage />} />
        </Routes>
      </Layout>
    </Router>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppProvider>
        <AppContent />
      </AppProvider>
    </QueryClientProvider>
  );
}

export default App;

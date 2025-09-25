// Common types used across the application
export interface CommandResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface TokenStatus {
  has_tokens: boolean;
  is_expired: boolean;
  expires_at: string | null;
  time_until_expiry: string;
}

export interface ProxyConfig {
  port: number;
  bind_address: string;
  debug_mode: boolean;
  openai_compatible: boolean;
}

export type LogLevel = 'Error' | 'Warning' | 'Info' | 'Debug';

export interface LogEntry {
  level: LogLevel;
  timestamp: string;
  message: string;
}

export interface AppState {
  tokenStatus: TokenStatus | null;
  proxyConfig: ProxyConfig | null;
  proxyRunning: boolean;
  logs: LogEntry[];
}
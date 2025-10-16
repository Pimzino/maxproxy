import { invoke } from '@tauri-apps/api/core';
import { CommandResult, TokenStatus, ProxyConfig, LogEntry, InitStatus, SystemInfo } from '@/types';

// OAuth API
export const startOAuthFlow = async (): Promise<CommandResult<string>> => {
  return invoke('start_oauth_flow');
};

export const exchangeOAuthCode = async (code: string): Promise<CommandResult<void>> => {
  return invoke('exchange_oauth_code', { code });
};

export const refreshToken = async (): Promise<CommandResult<void>> => {
  return invoke('refresh_token');
};

// Token Management API
export const getTokenStatus = async (): Promise<CommandResult<TokenStatus>> => {
  return invoke('get_token_status');
};

export const clearTokens = async (): Promise<CommandResult<void>> => {
  return invoke('clear_tokens');
};

// Proxy Server API
export const startProxyServer = async (): Promise<CommandResult<void>> => {
  return invoke('start_proxy_server');
};

export const stopProxyServer = async (): Promise<CommandResult<void>> => {
  return invoke('stop_proxy_server');
};

export const getProxyStatus = async (): Promise<CommandResult<boolean>> => {
  return invoke('get_proxy_status');
};

export const getProxyConfig = async (): Promise<CommandResult<ProxyConfig>> => {
  return invoke('get_proxy_config');
};

export const updateProxyConfig = async (config: ProxyConfig): Promise<CommandResult<void>> => {
  return invoke('update_proxy_config', { config });
};

export const getAccessibleEndpoints = async (): Promise<CommandResult<string[]>> => {
  return invoke('get_accessible_endpoints');
};

export const trustCertificate = async (): Promise<CommandResult<string>> => {
  return invoke('trust_proxy_certificate');
};

// Logging API
export const getLogs = async (): Promise<CommandResult<LogEntry[]>> => {
  return invoke('get_logs');
};

export const clearLogs = async (): Promise<CommandResult<void>> => {
  return invoke('clear_logs');
};

// Initialization API
export const getInitStatus = async (): Promise<CommandResult<InitStatus>> => {
  return invoke('get_init_status');
};

// System API
export const getSystemInfo = async (): Promise<CommandResult<SystemInfo>> => {
  return invoke('get_system_info');
};

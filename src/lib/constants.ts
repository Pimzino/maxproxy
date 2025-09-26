// Default to the repository discovered via `git remote`.
const DEFAULT_REPO_URL = "https://github.com/Pimzino/maxproxy";
export const REPO_URL = (import.meta.env.VITE_GITHUB_REPO_URL as string | undefined) ?? DEFAULT_REPO_URL;

const DEFAULT_DISCLAIMER = `EDUCATIONAL USE ONLY

MaxProxy is an independent project created for learning and experimentation. It is not sponsored, endorsed, or approved by Anthropic.

Key considerations:
- Relies on reverse-engineered Claude Code OAuth flows that may break or change without warning.
- Could violate Anthropic's Terms of Service or other agreements.
- Provides no warranty, guarantee, or support.
- May expose you to data loss, security issues, or account actions.
- Operation can stop at any time without notice.

By using MaxProxy you accept full responsibility for any consequences, including policy breaches, downtime, or security incidents.

For dependable access, use Claude Code or Anthropic's official APIs with console-issued API keys.`;

export const DISCLAIMER =
  (import.meta.env.VITE_APP_DISCLAIMER as string | undefined) ??
  DEFAULT_DISCLAIMER;

export function buildNewIssueUrl(title: string, body: string): string {
  const base = REPO_URL.replace(/\.git$/, "").replace(/\/$/, "");
  const params = new URLSearchParams({ title, body });
  return `${base}/issues/new?${params.toString()}`;
}

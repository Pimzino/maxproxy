# Tauri + React + Typescript

This template should help get you started developing with Tauri, React and Typescript in Vite.

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)

## About Page Configuration

You can configure the About page via environment variables (Vite reads `VITE_*`):

- `VITE_GITHUB_REPO_URL` — GitHub repository URL (e.g. `https://github.com/yourname/maxproxy`). Enables the “Open GitHub” button and directs the “Log an Issue” modal to your repo’s new issue page.
- `VITE_APP_DISCLAIMER` — Optional custom disclaimer text to display on the About page.

Create a `.env.local` file in the project root with values, for example:

```
VITE_GITHUB_REPO_URL=https://github.com/yourname/maxproxy
VITE_APP_DISCLAIMER=MaxProxy is provided as-is without warranty.
```

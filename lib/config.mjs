import fs from "fs";
import path from "path";
import os from "os";

// Single source of truth for the production endpoint. Every other URL is derived from it.
export const DEFAULT_MCP_URL = "https://api.agentlooker.ai/mcp";

// Environment variable names. These are the same names expanded by .mcp.json
// (via ${VAR:-default}), so the MCP server, the hooks, and setup.mjs all read one value.
export const ENV_MCP_URL = "AGENT_LOOKER_MCP_URL";
export const ENV_DASHBOARD_URL = "AGENT_LOOKER_DASHBOARD_URL";
export const ENV_TOKEN = "AGENT_LOOKER_API_TOKEN";

export const CLAUDE_DIR = process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), ".claude");
export const SETTINGS_PATH = path.join(CLAUDE_DIR, "settings.json");
export const CFG_PATH = path.join(os.homedir(), ".agent-looker.cfg");

export function dashboardUrlFor(mcpUrl) {
  return mcpUrl.replace(/\/mcp\/?$/, "") + "/dashboard";
}

function readJson(p) {
  try {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  } catch {
    return {};
  }
}

// setup.mjs writes values into ~/.claude/settings.json "env". Claude Code injects that block
// into every session (so hooks see it in process.env), but a plain `node setup.mjs` run does not,
// so we read it explicitly as a fallback.
const settingsEnv = readJson(SETTINGS_PATH).env ?? {};
const cfg = readJson(CFG_PATH);

function pick(name) {
  return process.env[name] ?? settingsEnv[name];
}

// Priority: process env > settings.json env > ~/.agent-looker.cfg (legacy) > default
export const MCP_URL = pick(ENV_MCP_URL) ?? cfg.mcpUrl ?? DEFAULT_MCP_URL;
export const DASHBOARD_URL = pick(ENV_DASHBOARD_URL) ?? cfg.dashboardUrl ?? dashboardUrlFor(MCP_URL);
export const MCP_TOKEN = pick(ENV_TOKEN) ?? cfg.token ?? "";

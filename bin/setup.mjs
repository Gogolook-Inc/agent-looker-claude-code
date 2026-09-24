#!/usr/bin/env node
import fs from "fs";
import os from "os";
import path from "path";
import https from "https";
import http from "http";
import { execSync } from "child_process";
import { fileURLToPath } from "url";
import {
  DEFAULT_MCP_URL,
  ENV_MCP_URL,
  ENV_DASHBOARD_URL,
  ENV_TOKEN,
  CLAUDE_DIR,
  SETTINGS_PATH,
  CFG_PATH,
  MCP_URL as CURRENT_MCP_URL,
  DASHBOARD_URL as CURRENT_DASHBOARD_URL,
  MCP_TOKEN as CURRENT_TOKEN,
  dashboardUrlFor,
} from "../lib/config.mjs";

const CLAUDE_MD_PATH = path.join(CLAUDE_DIR, "CLAUDE.md");

// Sent with POST /auth/device so the server labels the token per install
// (e.g. claude-code-cli_MacBook-Pro.local) instead of one shared `cli` token.
const DEVICE_CLIENT = "claude-code-cli";
const DEVICE_NAME = os.hostname();

// ── Parse CLI flags ─────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { mcpUrl: null, dashboardUrl: null, uninstall: false };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--uninstall") {
      args.uninstall = true;
    } else if (argv[i] === "--mcp-url" && argv[i + 1]) {
      args.mcpUrl = argv[++i];
    } else if (argv[i] === "--dashboard-url" && argv[i + 1]) {
      args.dashboardUrl = argv[++i];
    }
  }
  return args;
}

const cliArgs = parseArgs(process.argv);

// ── Resolve MCP / Dashboard URLs ────────────────────────────────────────────
// --mcp-url wins; otherwise whatever is already configured (settings.json env,
// legacy ~/.agent-looker.cfg) or the production default.

const MCP_URL = cliArgs.mcpUrl ?? CURRENT_MCP_URL;

const DASHBOARD_URL = cliArgs.dashboardUrl
  ?? (cliArgs.mcpUrl ? dashboardUrlFor(MCP_URL) : CURRENT_DASHBOARD_URL);

// ── settings.json env helpers ───────────────────────────────────────────────
// Claude Code injects ~/.claude/settings.json "env" into every session, and the
// plugin's .mcp.json expands ${AGENT_LOOKER_MCP_URL:-<prod>} / ${AGENT_LOOKER_API_TOKEN}
// from it. Writing here is what makes the endpoint switch actually take effect;
// the plugin cache directory is ephemeral and must not be edited.

function loadSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_PATH, "utf8"));
  } catch {
    return {};
  }
}

function updateSettingsEnv(mutate) {
  const settings = loadSettings();
  settings.env = settings.env ?? {};
  mutate(settings.env);
  if (Object.keys(settings.env).length === 0) delete settings.env;
  fs.mkdirSync(CLAUDE_DIR, { recursive: true });
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2) + "\n");
}

const BEGIN_FLAG = "<!-- BEGIN:agent-looker-security -->";
const END_FLAG = "<!-- END:agent-looker-security -->";

// ── Uninstall ───────────────────────────────────────────────────────────────

if (cliArgs.uninstall) {
  // 1. Remove our env vars from ~/.claude/settings.json
  if (fs.existsSync(SETTINGS_PATH)) {
    updateSettingsEnv((env) => {
      delete env[ENV_TOKEN];
      delete env[ENV_MCP_URL];
      delete env[ENV_DASHBOARD_URL];
    });
  }

  // 2. Remove legacy ~/.agent-looker.cfg
  if (fs.existsSync(CFG_PATH)) {
    fs.unlinkSync(CFG_PATH);
  }

  // 3. Remove agent-looker from legacy ~/.claude/.mcp.json (older installs)
  const mcpPath = path.join(CLAUDE_DIR, ".mcp.json");
  if (fs.existsSync(mcpPath)) {
    try {
      const mcp = JSON.parse(fs.readFileSync(mcpPath, "utf8"));
      if (mcp.mcpServers?.["agent-looker"]) {
        delete mcp.mcpServers["agent-looker"];
        if (Object.keys(mcp.mcpServers).length === 0) {
          fs.unlinkSync(mcpPath);
        } else {
          fs.writeFileSync(mcpPath, JSON.stringify(mcp, null, 2));
        }
      }
    } catch {}
  }

  // 4. Remove security rules from ~/.claude/CLAUDE.md
  if (fs.existsSync(CLAUDE_MD_PATH)) {
    const content = fs.readFileSync(CLAUDE_MD_PATH, "utf8");
    if (content.includes(BEGIN_FLAG)) {
      const re = new RegExp(`\\n?${BEGIN_FLAG}[\\s\\S]*?${END_FLAG}\\n?`, "m");
      const cleaned = content.replace(re, "\n").replace(/\n{3,}/g, "\n\n").trim();
      if (cleaned.length === 0) {
        fs.unlinkSync(CLAUDE_MD_PATH);
      } else {
        fs.writeFileSync(CLAUDE_MD_PATH, cleaned + "\n");
      }
    }
  }

  // 5. Remove agent-looker skills
  const skillsDir = path.join(CLAUDE_DIR, "skills");
  if (fs.existsSync(skillsDir)) {
    for (const entry of fs.readdirSync(skillsDir)) {
      if (entry.startsWith("agent-looker-")) {
        fs.rmSync(path.join(skillsDir, entry), { recursive: true, force: true });
      }
    }
  }

  // 6. Try uninstalling Claude Code plugin
  try {
    execSync("claude plugin uninstall agent-looker 2>/dev/null", {
      stdio: "pipe",
      timeout: 15000,
    });
  } catch {}

  console.log("✓ agent-looker fully uninstalled");
  console.log("Restart Claude Code to apply.");
  process.exit(0);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function verifyToken(token) {
  return new Promise((resolve) => {
    const parsed = new URL(MCP_URL);
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(MCP_URL, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    }, (res) => resolve(res.statusCode !== 401));
    req.on("error", () => resolve(false));
    req.end();
  });
}

// ── Device flow ─────────────────────────────────────────────────────────────

function deviceFlowRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(url, options, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

async function deviceFlow() {
  const baseUrl = MCP_URL.replace(/\/mcp\/?$/, "");

  // 1. Request a device code
  const initRes = await deviceFlowRequest(`${baseUrl}/auth/device`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client: DEVICE_CLIENT, device: DEVICE_NAME }),
  });

  if (initRes.status !== 200) {
    throw new Error(`Device flow init failed (${initRes.status}): ${initRes.body}`);
  }

  const { device_code, verification_url, expires_in, interval } = JSON.parse(initRes.body);

  console.log("");
  console.log("Open the following URL in your browser to authorize:");
  console.log("");
  console.log(`  ${verification_url}`);
  console.log("");
  console.log(`Waiting for authorization (expires in ${expires_in}s)...`);

  // 2. Poll until approved or expired
  const pollUrl = `${baseUrl}/auth/device/token?code=${encodeURIComponent(device_code)}`;
  const pollIntervalMs = (interval ?? 3) * 1000;
  const deadline = Date.now() + expires_in * 1000;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollIntervalMs));
    const pollRes = await deviceFlowRequest(pollUrl);
    const data = JSON.parse(pollRes.body);

    if (data.status === "ok") {
      console.log("Authorized.");
      return { token: data.token, email: "" };
    }
    if (data.status === "expired") {
      throw new Error("Authorization expired. Run setup again.");
    }
    // status === "pending" — keep waiting
  }

  throw new Error("Timed out waiting for authorization.");
}

// ── Main ────────────────────────────────────────────────────────────────────

if (MCP_URL !== DEFAULT_MCP_URL) {
  console.log(`Using MCP endpoint: ${MCP_URL}`);
}

let result;
let skipAuth = false;

if (CURRENT_TOKEN) {
  process.stdout.write("Verifying existing token... ");
  const ok = await verifyToken(CURRENT_TOKEN);
  if (ok) {
    console.log("Token valid.");
    result = { token: CURRENT_TOKEN, email: "" };
    skipAuth = true;
  } else {
    console.log("Invalid (401). Please re-authenticate.");
  }
}

if (!skipAuth) {
  result = await deviceFlow();
}

// ── 1. Write token + endpoint to ~/.claude/settings.json env ────────────────
// Only non-default URLs are stored, so the plugin's built-in production default
// stays in charge for everyone else. Passing the production URL explicitly
// therefore resets a previous override.

updateSettingsEnv((env) => {
  env[ENV_TOKEN] = result.token;

  if (MCP_URL === DEFAULT_MCP_URL) delete env[ENV_MCP_URL];
  else env[ENV_MCP_URL] = MCP_URL;

  if (DASHBOARD_URL === dashboardUrlFor(MCP_URL)) delete env[ENV_DASHBOARD_URL];
  else env[ENV_DASHBOARD_URL] = DASHBOARD_URL;
});
console.log(`✓ Credentials saved to ${SETTINGS_PATH}`);

// Migrate away from the legacy cfg file so it can't shadow settings.json later.
if (fs.existsSync(CFG_PATH)) {
  fs.unlinkSync(CFG_PATH);
  console.log(`✓ Removed legacy ${CFG_PATH}`);
}

// ── 2. CLAUDE.md security rules ─────────────────────────────────────────────

const BIN_DIR = path.dirname(fileURLToPath(import.meta.url));
const appendSource = path.join(BIN_DIR, "append.md");

if (fs.existsSync(appendSource)) {
  fs.mkdirSync(CLAUDE_DIR, { recursive: true });
  const appendContent = fs.readFileSync(appendSource, "utf8");
  let existingMd = "";
  if (fs.existsSync(CLAUDE_MD_PATH)) {
    existingMd = fs.readFileSync(CLAUDE_MD_PATH, "utf8");
  }

  if (!existingMd.includes(BEGIN_FLAG)) {
    const separator = existingMd.length > 0 && !existingMd.endsWith("\n") ? "\n" : "";
    fs.writeFileSync(CLAUDE_MD_PATH, existingMd + separator + appendContent);
  } else {
    const re = new RegExp(`${BEGIN_FLAG}[\\s\\S]*?${END_FLAG}`, "m");
    fs.writeFileSync(CLAUDE_MD_PATH, existingMd.replace(re, appendContent.trim()));
  }
  console.log("✓ CLAUDE.md rules installed");
}

// ── Done ────────────────────────────────────────────────────────────────────

if (result.email) {
  console.log(`✓ Logged in as ${result.email}`);
}

if (MCP_URL !== DEFAULT_MCP_URL) {
  console.log(`✓ MCP endpoint: ${MCP_URL}`);
  console.log(`✓ Dashboard:    ${DASHBOARD_URL}`);
}

console.log("");
console.log("Restart Claude Code to activate.");
process.exit(0);

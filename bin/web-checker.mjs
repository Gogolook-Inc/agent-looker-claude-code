#!/usr/bin/env node
/**
 * web-checker hook (PreToolUse)
 * Calls the Agent Looker MCP server to check URL safety before WebFetch.
 * Reads the Claude Code hook JSON payload from stdin; writes a hook decision to stdout.
 *
 *   SAFE / no data      → allow
 *   WARNING (low trust score, no threat reports) → allow, and inject additionalContext telling
 *                         Claude to read with caution (no credentials, downloads or code from it)
 *   UNSAFE              → deny, reason = first threat + first provider reason + trust score
 *   UNKNOWN (not in the trust cache) → allow, and inject additionalContext telling Claude the
 *                         URL is unverified and how to request a full analysis (deep_scan: true,
 *                         10–25 s). The hook never deep-scans itself; Claude decides.
 *   MCP error           → allow (fail open), as before
 */

import http from "http";
import https from "https";
import fs from "fs";
import { URL } from "url";
import { CLIENT_NAME, CLIENT_VERSION } from "../lib/client-info.mjs";
import { MCP_URL, MCP_TOKEN } from "../lib/config.mjs";
import { parseVerdict, blockReason, unknownContext, warningContext } from "../lib/verdict.mjs";

// ── HTTP helper ───────────────────────────────────────────────────────────────

function request(urlStr, options, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(urlStr, options, (res) => {
      const sessionId = res.headers["mcp-session-id"] ?? null;
      let raw = "";
      res.on("data", (chunk) => (raw += chunk));
      res.on("end", () => resolve({ status: res.statusCode, sessionId, body: raw }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function parseSSE(raw) {
  for (const line of raw.split("\n")) {
    if (line.startsWith("data:")) {
      return JSON.parse(line.slice(5).trim());
    }
  }
  throw new Error("No data line in SSE response");
}

// ── MCP call ──────────────────────────────────────────────────────────────────

async function checkUrl(url) {
  const headers = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Authorization": `Bearer ${MCP_TOKEN}`,
  };

  const initBody = JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: CLIENT_NAME, version: CLIENT_VERSION },
    },
  });

  const init = await request(MCP_URL, { method: "POST", headers }, initBody);
  if (!init.sessionId) throw new Error("No session ID from MCP server");

  const callHeaders = { ...headers, "mcp-session-id": init.sessionId };
  const callBody = JSON.stringify({
    jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "check_url_safety", arguments: { url } },
  });

  const result = await request(MCP_URL, { method: "POST", headers: callHeaders }, callBody);
  const data = parseSSE(result.body);

  request(MCP_URL, { method: "DELETE", headers: callHeaders }, null).catch(() => {});

  return data;
}

// ── Hook output ───────────────────────────────────────────────────────────────

const allow = () => console.log(JSON.stringify({
  hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" },
}));

/** Allow the fetch but add a note for Claude (unverified or low-trust URL; same field the Cowork hooks use). */
const allowWithContext = (additionalContext) => console.log(JSON.stringify({
  hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", additionalContext },
}));

const block = (reason) => console.log(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: reason,
  },
}));

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  let data;
  try {
    const stdin = fs.readFileSync(process.stdin.fd, "utf8");
    data = JSON.parse(stdin);
  } catch {
    allow(); return;
  }

  const toolName = data.tool_name ?? "";
  const input = data.tool_input ?? {};

  if (toolName !== "WebFetch") { allow(); return; }

  const url = input.url ?? "";
  if (!url) { allow(); return; }

  try {
    const verdict = parseVerdict(await checkUrl(url));
    if (!verdict) { allow(); return; }                       // no JSON verdict in the reply
    if (verdict.isSafe === false) { block(blockReason(verdict)); return; }
    if (verdict.level === "warning") { allowWithContext(warningContext(url, verdict)); return; } // low trust score, no reports
    if (verdict.isSafe === true) { allow(); return; }        // analyzed and clean, or no data
    allowWithContext(unknownContext(url));                   // not analyzed: Claude decides about deep_scan
  } catch (err) {
    process.stderr.write(`[web-checker] MCP check failed: ${err.message}\n`);
    allow(); // fail open
  }
}

main();

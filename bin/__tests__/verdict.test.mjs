import { test } from "node:test";
import assert from "node:assert/strict";
import { parseVerdict, blockReason, unknownContext, warningContext, DEEP_SCAN_SECONDS } from "../../lib/verdict.mjs";

const mcp = (...texts) => ({ result: { content: texts.map((text) => ({ type: "text", text })) } });
const json = (obj) => JSON.stringify(obj);

test("old backend shape (no status): boolean isSafe, string threats → analyzed", () => {
  assert.deepEqual(parseVerdict(mcp('SAFE: "u"', json({ url: "u", isSafe: true, threats: [] }))), {
    status: "analyzed", isSafe: true, level: "safe", threats: [], trustScore: null, reasons: [],
  });
  assert.deepEqual(parseVerdict(mcp(json({ url: "u", isSafe: false, threats: ["MALWARE", "SOCIAL_ENGINEERING"] }))), {
    status: "analyzed", isSafe: false, level: "unsafe", threats: ["MALWARE", "SOCIAL_ENGINEERING"], trustScore: null, reasons: [],
  });
});

test("oldest shape: threats as { threatType } objects are flattened", () => {
  const v = parseVerdict(mcp(json({ url: "u", isSafe: false, threats: [{ threatType: "MALWARE", platformType: "ANY" }, { nope: 1 }] })));
  assert.deepEqual(v.threats, ["MALWARE"]);
});

test("new backend: analyzed unsafe with trustScore and reasons (capped at 5)", () => {
  const reasons = ["r1", "r2", "r3", "r4", "r5", "r6"];
  const v = parseVerdict(mcp(json({ url: "u", status: "analyzed", isSafe: false, threats: ["PHISHING", "LOW_TRUST_SCORE"], trustScore: 1, reasons })));
  assert.deepEqual(v, { status: "analyzed", isSafe: false, level: "unsafe", threats: ["PHISHING", "LOW_TRUST_SCORE"], trustScore: 1, reasons: reasons.slice(0, 5) });
});

test("new backend: not_analyzed → isSafe null", () => {
  const v = parseVerdict(mcp("UNKNOWN: …", json({ url: "u", status: "not_analyzed", isSafe: null, threats: [], trustScore: null, reasons: [] })));
  assert.equal(v.status, "not_analyzed");
  assert.equal(v.isSafe, null);
  assert.equal(v.level, null);
});

test("new backend (NEO-509): level is read from the payload; warning keeps isSafe true", () => {
  const v = parseVerdict(mcp(json({ url: "u", status: "analyzed", isSafe: true, level: "warning", threats: ["MEDIUM_TRUST_SCORE"], trustScore: 36, reasons: ["r"] })));
  assert.deepEqual(v, { status: "analyzed", isSafe: true, level: "warning", threats: ["MEDIUM_TRUST_SCORE"], trustScore: 36, reasons: ["r"] });
  assert.equal(parseVerdict(mcp(json({ isSafe: false, level: "unsafe", threats: ["MALWARE"] }))).level, "unsafe");
  // an unknown level string falls back to the isSafe-derived one
  assert.equal(parseVerdict(mcp(json({ isSafe: true, level: "meh", threats: [] }))).level, "safe");
});

test("new backend: no_data → isSafe true", () => {
  const v = parseVerdict(mcp(json({ url: "u", status: "no_data", isSafe: true, threats: [], trustScore: null, reasons: [] })));
  assert.equal(v.status, "no_data");
  assert.equal(v.isSafe, true);
});

test("unknown status strings and junk fields fall back safely", () => {
  const v = parseVerdict(mcp(json({ url: "u", status: "weird", isSafe: "yes", threats: "MALWARE", trustScore: "1", reasons: "x" })));
  assert.deepEqual(v, { status: "analyzed", isSafe: null, level: null, threats: [], trustScore: null, reasons: [] });
});

test("non-JSON or JSON without isSafe → null (fail open upstream)", () => {
  assert.equal(parseVerdict(mcp("just text")), null);
  assert.equal(parseVerdict(mcp(json({ hello: 1 }))), null);
  assert.equal(parseVerdict({}), null);
  assert.equal(parseVerdict(undefined), null);
});

test("blockReason: first threat, first reason, trust score; degrades gracefully", () => {
  assert.equal(
    blockReason({ threats: ["PHISHING", "LOW_TRUST_SCORE"], reasons: ["This website has been reported for Phishing by IPQS", "other"], trustScore: 1 }),
    "URL blocked by safety check: PHISHING — This website has been reported for Phishing by IPQS (trust score 1/100)"
  );
  assert.equal(blockReason({ threats: ["MALWARE"], reasons: [], trustScore: null }), "URL blocked by safety check: MALWARE");
  assert.equal(blockReason({ threats: [], reasons: [], trustScore: null }), "URL blocked by safety check: UNSAFE");
});

test("unknownContext names the URL, deep_scan and the delay, and never the provider", () => {
  const text = unknownContext("https://x.test/p");
  assert.match(text, /"https:\/\/x\.test\/p"/);
  assert.match(text, /UNKNOWN/);
  assert.match(text, /deep_scan: true/);
  assert.ok(text.includes(DEEP_SCAN_SECONDS));
  assert.doesNotMatch(text.toLowerCase(), /scamadviser|google/);
});

test("warningContext names the URL, the score, WARNING, the caution rule and deep_scan; never the provider", () => {
  const text = warningContext("https://x.test/p", { trustScore: 36, reasons: ["High number of suspicious websites on this IP-address"] });
  assert.match(text, /"https:\/\/x\.test\/p" has a LOW trust score \(36\/100\) but no threat reports \(WARNING\)/);
  assert.match(text, /Reason given: High number of suspicious websites on this IP-address\./);
  assert.match(text, /do not enter credentials, download or run anything from it/);
  assert.match(text, /deep_scan: true/);
  assert.doesNotMatch(text.toLowerCase(), /scamadviser|google/);
});

test("warningContext degrades without a score or reasons", () => {
  const text = warningContext("https://x.test/", { trustScore: null, reasons: [] });
  assert.match(text, /has a LOW trust score but no threat reports \(WARNING\)\. You may read it/);
  assert.doesNotMatch(text, /Reason given/);
});

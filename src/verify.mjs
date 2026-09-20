// VaultBytes Verify GitHub Action: submit a job for the pushed commit, poll until it finishes or times out,
// write the job summary, and hand the decision to the enforcing step of action.yml.
//
// Zero dependencies (Node >= 18: global fetch, AbortSignal.timeout). The customer token is read from the
// VBV_TOKEN environment variable, sent only in the Authorization header, and never written to stdout, stderr,
// the job summary, the outputs or result.json. Every message that can carry server text is passed through
// scrub() first, which also removes the token if a server ever echoed it.

import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { DEFAULT_API_URL } from "./service-url.mjs";

export const VERSION = "0.1.0";
// "auto": the worker detects it (SPEC v0.3). "custom": this repository ships its own adapter at
// .vaultbytes/adapter.json and that adapter must be what runs -- never one of ours (SPEC v0.14).
export const LIBRARIES = new Set(["auto", "lattigo", "openfhe", "custom"]);
export const VERDICTS = new Set(["PASS", "FAIL", "ERROR", "REFUSED"]);
export const JOB_ID_RE = /^j_[0-9A-HJKMNP-TV-Z]{26}$/;
const SUITE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

export class ActionError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind; // config | auth | api | protocol | timeout
  }
}

// ---------------------------------------------------------------- configuration

export function readConfig(env) {
  const token = env.VBV_TOKEN ?? "";
  if (token === "") throw new ActionError("config", "input 'token' is empty: pass it from a repository secret, e.g. token: ${{ secrets.VBV_TOKEN }}");
  if (token.length > 4096 || /[\s\x00-\x1f\x7f]/.test(token)) throw new ActionError("config", "input 'token' is malformed (whitespace or control characters)");

  // api-url: the input, else a VBV_API_URL variable of the workflow, else the service URL baked in at deploy time
  const rawUrl = (env.VBV_INPUT_API_URL ?? "").trim() || (env.VBV_API_URL ?? "").trim() || DEFAULT_API_URL;
  const apiUrl = parseApiUrl(rawUrl);
  if (new URL(apiUrl).hostname.endsWith(".invalid")) {
    throw new ActionError("config", "the VaultBytes Verify service URL is not configured in this build of the action; set input 'api-url'");
  }
  const library = (env.VBV_LIBRARY ?? "").trim().toLowerCase() || "auto";
  if (!LIBRARIES.has(library)) throw new ActionError("config", "input 'library' must be auto, lattigo, openfhe or custom");
  const suite = (env.VBV_SUITE ?? "").trim() || "auto";
  if (!SUITE_RE.test(suite)) throw new ActionError("config", "input 'suite' is not a valid suite name");
  const failOn = (env.VBV_FAIL_ON ?? "").trim().toUpperCase() || "FAIL"; // SPEC v0.3 default
  if (failOn !== "FAIL" && failOn !== "ERROR") throw new ActionError("config", "input 'fail-on' must be FAIL or ERROR");
  const reportLink = (env.VBV_REPORT_LINK ?? "").trim().toLowerCase() || "auto";
  if (!["auto", "always", "never"].includes(reportLink)) throw new ActionError("config", "input 'report-link' must be auto, always or never");

  const timeoutS = intIn(env.VBV_TIMEOUT_SECONDS, 4500, 5, 6 * 3600, "timeout-seconds");
  const pollS = intIn(env.VBV_POLL_INTERVAL_SECONDS, 10, 1, 300, "poll-interval-seconds");
  // options are sent only when set; omitted means "auto" on the service side (SPEC v0.3)
  const options = {};
  if ((env.VBV_JOB_TIMEOUT_SECONDS ?? "").trim() !== "") options.timeout_s = intIn(env.VBV_JOB_TIMEOUT_SECONDS, 3600, 60, 3600, "job-timeout-seconds");
  if ((env.VBV_WORST_CASE ?? "").trim() !== "") options.worst_case = parseBool(env.VBV_WORST_CASE, "worst-case");

  const sha = (env.GITHUB_SHA ?? "").trim().toLowerCase();
  if (!SHA_RE.test(sha)) throw new ActionError("config", "GITHUB_SHA is not a 40-hex commit; run this action from a push or pull_request workflow");
  const repo = (env.GITHUB_REPOSITORY ?? "").trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new ActionError("config", "GITHUB_REPOSITORY is missing or malformed");
  const server = (env.GITHUB_SERVER_URL ?? "https://github.com").replace(/\/+$/, "");
  const ref = (env.GITHUB_REF ?? "").trim();

  return {
    token, apiUrl, library, suite, failOn, reportLink, timeoutS, pollS, options,
    target: { kind: "git", url: `${server}/${repo}.git`, ref, commit: sha },
  };
}

// The request body: the target always; library, suite and options only when the customer chose them.
export function jobBody(cfg) {
  const body = { target: cfg.target };
  if (cfg.library !== "auto") body.library = cfg.library;
  if (cfg.suite !== "auto") body.suite = cfg.suite;
  if (Object.keys(cfg.options).length) body.options = cfg.options;
  return body;
}

export function parseApiUrl(raw) {
  let u;
  try {
    u = new URL(String(raw).trim());
  } catch {
    throw new ActionError("config", "input 'api-url' is not a valid URL");
  }
  if (u.username || u.password) throw new ActionError("config", "input 'api-url' must not contain credentials");
  if (u.search || u.hash) throw new ActionError("config", "input 'api-url' must not contain a query or fragment");
  const loopback = LOOPBACK.has(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    // The bearer token must never cross the network in clear text. Plain http is accepted only for a loopback
    // address (local tests); it is refused before any request is made.
    throw new ActionError("config", "input 'api-url' must use https:// (plain http is allowed only for 127.0.0.1/localhost)");
  }
  return u.origin + u.pathname.replace(/\/+$/, "");
}

function intIn(raw, dflt, lo, hi, name) {
  if (raw === undefined || String(raw).trim() === "") return dflt;
  const s = String(raw).trim();
  if (!/^\d+$/.test(s)) throw new ActionError("config", `input '${name}' must be a whole number`);
  const n = Number(s);
  if (n < lo || n > hi) throw new ActionError("config", `input '${name}' must be between ${lo} and ${hi}`);
  return n;
}

function parseBool(raw, name) {
  const s = String(raw).trim().toLowerCase();
  if (s === "true") return true;
  if (s === "false" || s === "") return false;
  throw new ActionError("config", `input '${name}' must be true or false`);
}

// ---------------------------------------------------------------- pure helpers

// SPEC v0.1 section 2 (+ v0.2 `reason`): the only result fields a customer may see. Anything else the API returns (for example the
// internal kit_commit or seal.seal_commit) is dropped before the summary and the artifact are written.
// SPEC v0.2 adds `reason` (a short customer-facing line, set on REFUSED results, where `counts` is null).
// SPEC v0.3 adds the detected library version (`library_version`).
// SPEC v0.4 adds `coverage` {cross_backend: done|unavailable, partner, reason}.
// SPEC v0.14 adds `adapter` {name, level, timeout_s}: which adapter ran and at which conformance level.
const TOP_FIELDS = ["job_id", "verdict", "reason", "library", "library_version", "commit", "artifact_sha256", "suite",
  "counts", "precision", "gaps", "seal", "coverage", "adapter", "kit_version", "started_at", "finished_at", "duration_s"];
const SUB_FIELDS = {
  counts: ["cases", "within", "beyond", "errors"],
  precision: ["min_bits", "median_bits"],
  seal: ["plan_sha256", "expected_index_sha256"],
  coverage: ["cross_backend", "partner", "reason"],
  adapter: ["name", "level", "timeout_s"],
};

export function customerView(result) {
  if (!result || typeof result !== "object" || Array.isArray(result)) return null;
  const out = {};
  for (const k of TOP_FIELDS) {
    if (!(k in result)) continue;
    const v = result[k];
    if (SUB_FIELDS[k]) {
      if (v && typeof v === "object" && !Array.isArray(v)) {
        out[k] = {};
        for (const f of SUB_FIELDS[k]) if (f in v) out[k][f] = v[f];
      } else {
        out[k] = null;
      }
    } else if (k === "reason") {
      out[k] = typeof v === "string" ? v.slice(0, 300) : null;
    } else if (k === "gaps") {
      out[k] = Array.isArray(v) ? v.slice(0, 200) : [];
    } else {
      out[k] = v;
    }
  }
  return out;
}

// Remove the token (if present) and control characters from text that may reach a log, and cap its length.
export function scrub(text, token, max = 300) {
  let s = String(text ?? "");
  if (token && token.length >= 4) s = s.split(token).join("***");
  s = s.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim();
  return s.length > max ? s.slice(0, max) + "..." : s;
}

// Escape text for a GitHub workflow command message (::error::...).
export function escapeCommand(s) {
  return String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

// Escape server-supplied text for the job summary (Markdown + HTML): no tags, no links, no table breaks, no line
// breaks. Truncation happens first, so an escape sequence is never cut in half.
export function md(value, max = 200) {
  if (value === null || value === undefined || value === "") return "n/a";
  let s = String(value).replace(/[\x00-\x1f\x7f]+/g, " ");
  if (s.length > max) s = s.slice(0, max) + "...";
  return s
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
    .replace(/[|`*_[\]()!#~\\]/g, (c) => "\\" + c);
}

// The report link is written into the summary as a Markdown link, so it must be on the API's own origin (part A
// serves reports from /v1/reports/...; the API origin is https, or loopback http in tests) and contain no character
// that could close the link or start markup.
export function safeReportUrl(raw, apiUrl) {
  if (typeof raw !== "string" || raw.length > 2048) return null;
  if (!/^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/[A-Za-z0-9._~\/?&=%+-]*$/.test(raw)) return null;
  try {
    return new URL(raw).origin === new URL(apiUrl).origin ? raw : null;
  } catch {
    return null;
  }
}

// Next poll delay in ms: grows by 1.5x per attempt from the base interval, capped at 60 s, with +/-10% jitter,
// and never shorter than a server Retry-After.
export function nextDelayMs(attempt, baseS, retryAfterS = 0, rand = Math.random) {
  const grown = Math.min(60, baseS * Math.pow(1.5, attempt));
  const jitter = grown * (0.9 + 0.2 * rand());
  return Math.round(Math.max(jitter, retryAfterS) * 1000);
}

export function parseRetryAfter(value) {
  if (!value) return 0;
  const n = Number(value);
  if (Number.isFinite(n) && n >= 0) return Math.min(n, 300);
  const t = Date.parse(value);
  return Number.isFinite(t) ? Math.max(0, Math.min(300, (t - Date.now()) / 1000)) : 0;
}

// The pass/fail decision. FAIL always fails. ERROR and REFUSED fail unless fail-on is FAIL. Anything the action
// cannot interpret fails (fail closed).
export function decide(verdict, failOn) {
  if (verdict === "PASS") return { pass: true, level: "notice" };
  if (verdict === "FAIL") return { pass: false, level: "error" };
  if (verdict === "ERROR" || verdict === "REFUSED") {
    return failOn === "FAIL" ? { pass: true, level: "warning" } : { pass: false, level: "error" };
  }
  return { pass: false, level: "error" };
}

// SPEC v0.14 section 2: the conformance level the adapter reported. Level 1 checks each program's final outputs
// only; level 2 also checks per-operation values and the declared metadata, which is what catches the silent
// defects (a mislabelled scale, an aliased operand). A level 1 PASS must never read like a level 2 PASS, so the
// summary gives the level its own row and says out loud what a level 1 PASS does not cover. An absent or
// unrecognised level is reported as such -- never quietly rendered as the stronger one.
// The labels stay free of the characters md() escapes, so the row reads as written even though it is escaped like
// any other value: nothing here is ever allowed to skip escaping just because we wrote it.
export const LEVEL_LABEL = {
  1: "Level 1 - final outputs only",
  2: "Level 2 - full trace: final outputs, per-operation values and declared metadata",
};

export function conformance(result) {
  const a = result && typeof result === "object" ? result.adapter : null;
  if (!a || typeof a !== "object" || Array.isArray(a)) return { level: null, label: "not reported", name: null };
  const level = a.level === 1 || a.level === 2 ? a.level : null;
  return {
    level,
    label: level === null ? "not reported" : LEVEL_LABEL[level],
    name: typeof a.name === "string" && a.name !== "" ? a.name : null,
  };
}

export function isPrivateRepo(eventPayload) {
  return Boolean(eventPayload && eventPayload.repository && eventPayload.repository.private === true);
}

export function showReportLink(policy, eventPayload) {
  if (policy === "always") return true;
  if (policy === "never") return false;
  return isPrivateRepo(eventPayload); // auto: a signed report URL is shown only in a private repository
}

export function renderSummary(o) {
  const L = [];
  const r = o.result || {};
  const verdict = o.verdict || "none";
  L.push(`## VaultBytes Verify: ${md(verdict)}`);
  L.push("");
  L.push(o.pass ? `Check: **passed** (fail-on: ${md(o.failOn)})` : `Check: **failed** (fail-on: ${md(o.failOn)})`);
  if (o.error) L.push("", `> ${md(o.error)}`);
  L.push("", "| Field | Value |", "| --- | --- |");
  L.push(`| Job | ${md(o.jobId)} |`);
  L.push(`| Status | ${md(o.status)} |`);
  if (r.reason) L.push(`| Reason | ${md(r.reason)} |`);
  const detected = o.library === "auto" && r.library ? " (detected)" : "";
  L.push(`| Library | ${md(r.library ?? o.library)}${detected} |`);
  if (r.library_version !== undefined) L.push(`| Library version | ${md(r.library_version)} |`);
  L.push(`| Suite | ${md(r.suite ?? o.suite)} |`);
  const conf = conformance(r);
  L.push(`| Conformance | ${md(conf.label)}${conf.name ? ` (adapter: ${md(conf.name, 60)})` : ""} |`);
  if (r.artifact_sha256) L.push(`| Artifact sha256 | ${md(r.artifact_sha256)} |`);
  else L.push(`| Commit | ${md(r.commit ?? o.commit)} |`);
  if (r.kit_version !== undefined) L.push(`| Kit version | ${md(r.kit_version)} |`);
  const c = r.counts || {};
  L.push(`| Cases | ${md(c.cases)} |`);
  L.push(`| Within bound | ${md(c.within)} |`);
  L.push(`| Beyond bound | ${md(c.beyond)} |`);
  L.push(`| Errors | ${md(c.errors)} |`);
  const p = r.precision || {};
  L.push(`| Precision, min bits | ${md(p.min_bits)} |`);
  L.push(`| Precision, median bits | ${md(p.median_bits)} |`);
  if (r.duration_s !== undefined) L.push(`| Duration (s) | ${md(r.duration_s)} |`);
  const gaps = Array.isArray(r.gaps) ? r.gaps : [];
  L.push(`| Gaps (informational) | ${gaps.length} |`);
  const cov = r.coverage;
  if (cov && typeof cov === "object") {
    if (cov.cross_backend === "done") {
      L.push(`| Cross-backend coverage | done (partner: ${md(cov.partner)}) |`);
    } else {
      // SPEC v0.4: the partner never decides the verdict; say plainly that the comparison did not happen
      L.push(`| Cross-backend coverage | cross-backend comparison not performed${cov.reason ? ` (${md(cov.reason)})` : ""} |`);
    }
  }
  if (gaps.length) {
    L.push("", "Gaps:");
    for (const g of gaps.slice(0, 10)) L.push(`- ${md(typeof g === "string" ? g : JSON.stringify(g))}`);
    if (gaps.length > 10) L.push(`- ... and ${gaps.length - 10} more (see result.json)`);
  }
  // SPEC v0.14 section 2: a level 1 PASS is a weaker statement than a level 2 PASS, and the summary is where a
  // reviewer decides how much the green check is worth. Say the difference in the summary, not only in the docs.
  if (verdict === "PASS" && conf.level === 1) {
    L.push("", "> Level 1 conformance: this PASS covers each program's final outputs only. It does not cover "
      + "per-operation values or declared metadata, which is what a Level 2 (full trace) run checks.");
  }
  L.push("");
  if (o.reportRejected) L.push("Report: the service returned a report link that is not a plain URL on the API's origin; it is not shown.");
  else if (o.reportUrl && o.showLink) L.push(`Report: [REPORT.html](${o.reportUrl}) (signed link; it expires)`);
  else if (o.reportUrl) L.push("Report: a signed report link exists but is not shown here (public repository or report-link: never). Retrieve it with the job ID.");
  else L.push("Report: none");
  L.push("", `<sub>vaultbytes-verify-action ${VERSION}</sub>`, "");
  return L.join("\n");
}

// ---------------------------------------------------------------- HTTP

async function request(cfg, method, path, body, log) {
  const url = cfg.apiUrl + path;
  const headers = {
    Authorization: `Bearer ${cfg.token}`,
    Accept: "application/json",
    "User-Agent": `vaultbytes-verify-action/${VERSION}`,
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(url, {
      method, headers, redirect: "error", // never follow a redirect with the bearer token
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30000),
    });
  } catch (e) {
    return { transient: true, status: 0, error: scrub(e && e.cause ? e.cause.code || e.message : e, cfg.token, 120) };
  }
  let text = "";
  try { text = await res.text(); } catch { text = ""; }
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  const retryAfter = parseRetryAfter(res.headers.get("retry-after"));
  const transient = res.status === 429 || res.status >= 500;
  const serverMsg = json && typeof json === "object" ? json.error || json.detail || json.message || "" : "";
  if (log && transient) log(`HTTP ${res.status} from ${method} ${path}: will retry`);
  return { transient, status: res.status, json, retryAfter, serverMsg: scrub(serverMsg, cfg.token) };
}

function fatalForStatus(r, what) {
  if (r.status === 401 || r.status === 403) {
    return new ActionError("auth", `authentication failed (HTTP ${r.status}) on ${what}: the token was rejected. Check that the repository secret holds a current VaultBytes Verify token (it may have been revoked).`);
  }
  if (r.status === 404) return new ActionError("api", `${what}: not found (HTTP 404). Check input 'api-url'.`);
  return new ActionError("api", `${what} was rejected (HTTP ${r.status})${r.serverMsg ? ": " + r.serverMsg : ""}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- main flow

export async function run(env, io) {
  const log = io.log;
  const started = io.now();
  const out = { status: null, verdict: null, jobId: null, result: null, reportUrl: null, error: null, kind: null };
  // Defence in depth: GitHub already masks values that come from `secrets.*`; this also masks a token that was
  // passed some other way. The runner consumes this command and does not print it.
  const tok = env.VBV_TOKEN || "";
  if (env.GITHUB_ACTIONS === "true" && tok.length >= 4 && !/[\s\x00-\x1f\x7f]/.test(tok)) log(`::add-mask::${tok}`);
  let cfg;
  try {
    cfg = readConfig(env);
  } catch (e) {
    return finish({ ...out, error: e.message, kind: e.kind }, null, env, io);
  }
  out.library = cfg.library; out.suite = cfg.suite; out.commit = cfg.target.commit; out.failOn = cfg.failOn;
  const deadline = started + cfg.timeoutS * 1000;

  try {
    // 1. submit (retried on transient errors; the service is idempotent on the job content)
    const body = jobBody(cfg);
    log(`Submitting commit ${cfg.target.commit} of ${cfg.target.url} (library: ${cfg.library}, suite: ${cfg.suite}) to ${cfg.apiUrl}`);
    let attempt = 0;
    for (;;) {
      const r = await request(cfg, "POST", "/v1/jobs", body, log);
      if (!r.transient) {
        if (r.status !== 202 && r.status !== 200) throw fatalForStatus(r, "job submission");
        const id = r.json && r.json.job_id;
        if (typeof id !== "string" || !JOB_ID_RE.test(id)) throw new ActionError("protocol", "job submission returned no valid job_id");
        out.jobId = id;
        // server text: only a known status is kept (a crafted value could otherwise inject a workflow command)
        const st0 = r.json && r.json.status;
        out.status = ["queued", "running", "done", "error"].includes(st0) ? st0 : "queued";
        break;
      }
      const wait = nextDelayMs(attempt++, cfg.pollS, r.retryAfter);
      if (io.now() + wait > deadline) throw new ActionError("timeout", `timed out after ${cfg.timeoutS} s: the API did not accept the job (last: ${r.status ? "HTTP " + r.status : r.error})`);
      await io.sleep(wait);
    }
    log(`Job ${out.jobId} accepted (status: ${out.status})`);

    // 2. poll with backoff until done/error or the deadline
    attempt = 0;
    for (;;) {
      const r = await request(cfg, "GET", `/v1/jobs/${out.jobId}`, undefined, log);
      let retryAfter = 0;
      if (r.transient) {
        retryAfter = r.retryAfter;
      } else if (r.status !== 200) {
        throw fatalForStatus(r, `status of job ${out.jobId}`);
      } else {
        const st = r.json && r.json.status;
        if (!["queued", "running", "done", "error"].includes(st)) throw new ActionError("protocol", `job ${out.jobId}: unknown status in API response`);
        out.status = st;
        if (st === "done" || st === "error") {
          out.result = customerView(r.json.result);
          const v = out.result && out.result.verdict;
          out.verdict = st === "error" ? (VERDICTS.has(v) ? v : "ERROR") : v;
          if (!VERDICTS.has(out.verdict)) throw new ActionError("protocol", `job ${out.jobId} finished without a valid verdict`);
          if (out.result && out.result.job_id && out.result.job_id !== out.jobId) throw new ActionError("protocol", "result belongs to a different job");
          out.reportUrl = safeReportUrl(r.json.report_url, cfg.apiUrl);
          out.reportRejected = r.json.report_url != null && out.reportUrl === null;
          break;
        }
      }
      const wait = nextDelayMs(attempt++, cfg.pollS, retryAfter);
      const elapsed = Math.round((io.now() - started) / 1000);
      if (io.now() + wait > deadline) {
        throw new ActionError("timeout", `timed out after ${cfg.timeoutS} s waiting for job ${out.jobId} (last status: ${out.status}). The job may still finish; look it up by its ID.`);
      }
      log(`Job ${out.jobId}: ${out.status}, ${elapsed} s elapsed, next check in ${Math.round(wait / 1000)} s`);
      await io.sleep(wait);
    }
  } catch (e) {
    if (!(e instanceof ActionError)) throw e;
    out.error = e.message; out.kind = e.kind;
  }
  return finish(out, cfg, env, io);
}

function finish(out, cfg, env, io) {
  const failOn = (cfg && cfg.failOn) || "ERROR";
  const d = out.error ? { pass: false, level: "error" } : decide(out.verdict, failOn);
  let eventPayload = null;
  try { eventPayload = env.GITHUB_EVENT_PATH ? JSON.parse(io.readFile(env.GITHUB_EVENT_PATH)) : null; } catch { eventPayload = null; }
  const showLink = cfg ? showReportLink(cfg.reportLink, eventPayload) : false;

  // result.json: the customer-visible result fields only (customerView), for the artifact. The signed report URL is
  // not stored in it.
  let resultPath = "";
  if (out.jobId && out.status && (out.status === "done" || out.status === "error")) {
    const dir = join(env.RUNNER_TEMP || io.tmpdir(), "vaultbytes-verify", out.jobId);
    io.mkdir(dir);
    resultPath = join(dir, "result.json");
    const doc = out.result || { job_id: out.jobId, verdict: out.verdict, note: "the service returned no result summary" };
    io.writeFile(resultPath, JSON.stringify(doc, null, 2) + "\n");
  }

  const summary = renderSummary({
    ...out, failOn, pass: d.pass, showLink,
    library: out.library, suite: out.suite, commit: out.commit,
  });
  const token = cfg ? cfg.token : env.VBV_TOKEN;
  if (env.GITHUB_STEP_SUMMARY) io.append(env.GITHUB_STEP_SUMMARY, scrubMultiline(summary, token));

  const gated = out.verdict === "ERROR" || out.verdict === "REFUSED"; // the only verdicts fail-on changes
  const reason = out.error
    ? `${out.kind}: ${out.error}`
    : `verdict ${out.verdict}${gated ? ` (fail-on: ${failOn})` : ""}`;
  const outputs = {
    "job-id": out.jobId || "",
    status: out.status || "",
    verdict: out.verdict || "",
    decision: d.pass ? "pass" : "fail",
    reason: scrub(reason, token, 400),
    "result-path": resultPath,
    "report-url": showLink && out.reportUrl ? out.reportUrl : "",
  };
  if (env.GITHUB_OUTPUT) {
    io.append(env.GITHUB_OUTPUT, Object.entries(outputs).map(([k, v]) => `${k}=${String(v).replace(/[\r\n]/g, " ")}\n`).join(""));
  }
  const title = "VaultBytes Verify";
  if (out.error) io.log(`::error title=${title}::${escapeCommand(scrub(out.error, token, 400))}`);
  else io.log(`::${d.level} title=${title}::${escapeCommand(`verdict ${out.verdict} for job ${out.jobId}${gated ? ` (fail-on: ${failOn})` : ""}`)}`);
  return outputs;
}

function scrubMultiline(text, token) {
  return token && token.length >= 4 ? String(text).split(token).join("***") : String(text);
}

// main.mjs's last-line guard (SPEC v0.11 hardening): true once run() produced a verdict or a
// status -- i.e. the job was actually submitted, whatever the outcome. main.mjs exits non-zero
// when this is false, independent of action.yml's own "Enforce the decision" step, so an upstream
// no-op is never mistaken for a completed, passing check.
export function ranSomething(outputs) {
  return Boolean(outputs && (outputs.verdict || outputs.status));
}

// ---------------------------------------------------------------- entry point

export const realIO = {
  log: (m) => process.stdout.write(m + "\n"),
  now: () => Date.now(),
  sleep,
  mkdir: (d) => mkdirSync(d, { recursive: true, mode: 0o700 }),
  writeFile: (p, s) => writeFileSync(p, s, { mode: 0o600 }),
  append: (p, s) => appendFileSync(p, s),
  readFile: (p) => readFileSync(p, "utf8"),
  tmpdir: () => process.env.TMPDIR || "/tmp",
};

// verify.mjs is a library only -- it never calls run() itself. It used to gate a self-invocation
// behind an "is this the entry module" check (import.meta.url === pathToFileURL(argv[1]).href),
// but that is a fail-open design: if the two ever differ for a reason that has nothing to do with
// "was this imported" -- e.g. a symlink a container's base image resolves on one side and not the
// other (act's local-action staging under /var/run/act/actions/... hit exactly this on
// catthehacker/ubuntu:act-latest, where /var/run is itself a symlink to /run) -- run() silently
// never executes: no error, no output, exit 0, and a check that tested nothing reports green.
// The fix is not a more tolerant comparison; it is not gating the call at all. main.mjs is the
// action's real entry point (action.yml's "Submit and wait" step runs it, not this file), has no
// other job, and always calls run().

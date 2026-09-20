// Stub of the VaultBytes Verify HTTP API v1 (SPEC section 3, v0.1 result fields) for testing the Action.
// Test use only.
//
//   node client/test/stub-api.mjs --port 18787 [--log requests.jsonl]
//
// The scenario is chosen by the token's prefix; the rest of the token is an arbitrary nonce, so a test can grep
// its whole output for that token and prove it was never printed:
//   vbvtest_pass_*    queued -> running -> done, verdict PASS (with one informational gap)
//   vbvtest_fail_*    ... done, verdict FAIL
//   vbvtest_error_*   ... status "error", verdict ERROR (build failure in the sandbox)
//   vbvtest_slow_*    stays "running" forever (drives the timeout arm)
//   vbvtest_flaky_*   POST answers 503 + Retry-After once, GET answers 429 once, then behaves like pass
//   vbvtest_internal_* like pass, but the result also carries internal fields (kit_commit, seal.seal_commit)
//   vbvtest_refused_* done, verdict REFUSED, counts null, a short reason (SPEC v0.2: fetch exited 3)
//   vbvtest_hostile_* REFUSED whose reason, gaps, kit_version and report_url carry HTML/Markdown injection
//   anything else     401 {"error": "invalid token"}
// The request body is validated against the SPEC job shape; a malformed body gets 400, so a passing arm also
// proves that the Action sends a conforming request. The stub never logs the token: only a short hash of it.

import { createHash, randomInt } from "node:crypto";
import { appendFileSync } from "node:fs";
import { createServer } from "node:http";

import { HOSTILE } from "./hostile.mjs";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith("--") ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const PORT = Number(args.port || 18787);
const LOG = args.log || "";
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const jobs = new Map(); // job_id -> {owner, scenario, spec, polls, created}
const idem = new Map(); // owner+content -> job_id
const flaky = new Map(); // owner -> {postFailed, getFailed}

const newJobId = () => "j_" + Array.from({ length: 26 }, () => CROCKFORD[randomInt(32)]).join("");
const tokenHash = (t) => createHash("sha256").update(t).digest("hex").slice(0, 12);

function scenarioOf(token) {
  const m = /^vbvtest_(pass|fail|error|slow|flaky|internal|refused|hostile)_[A-Za-z0-9]{8,64}$/.exec(token);
  return m ? m[1] : null;
}

function validateSpec(b) {
  // SPEC v0.3: only target is required; any library, suite or options given must still be valid
  if (!b || typeof b !== "object") return "body must be a JSON object";
  const t = b.target;
  if (!t || t.kind !== "git") return "target.kind must be git";
  if (typeof t.url !== "string" || !/^https:\/\/[^/]+\/[^/]+\/[^/]+\.git$/.test(t.url)) return "target.url must be an https git URL";
  if (typeof t.commit !== "string" || !/^[0-9a-f]{40}$/.test(t.commit)) return "target.commit must be 40 hex";
  if (typeof t.ref !== "string") return "target.ref must be a string";
  // SPEC v0.14: "custom" means the repository ships its own adapter at .vaultbytes/adapter.json
  if ("library" in b && !["auto", "lattigo", "openfhe", "custom"].includes(b.library)) return "library must be auto, lattigo, openfhe or custom";
  if ("suite" in b && (typeof b.suite !== "string" || !b.suite)) return "suite must be a non-empty string";
  if ("options" in b) {
    const o = b.options;
    if (!o || typeof o !== "object") return "options must be an object";
    if ("worst_case" in o && typeof o.worst_case !== "boolean") return "options.worst_case must be a boolean";
    if ("timeout_s" in o && (!Number.isInteger(o.timeout_s) || o.timeout_s < 60 || o.timeout_s > 3600)) return "options.timeout_s must be 60..3600";
    const extraO = Object.keys(o).filter((k) => !["worst_case", "timeout_s"].includes(k));
    if (extraO.length) return "unexpected options: " + extraO.join(",");
  }
  const extra = Object.keys(b).filter((k) => !["target", "library", "suite", "options"].includes(k));
  if (extra.length) return "unexpected fields: " + extra.join(",");
  return null;
}

function resultFor(job, verdict) {
  const s = { ...job.spec, library: job.spec.library && job.spec.library !== "auto" ? job.spec.library : "lattigo",
    suite: job.spec.suite && job.spec.suite !== "auto" ? job.spec.suite : "auto" };
  if (job.scenario === "hostile") {
    return { job_id: job.id, verdict, reason: HOSTILE.reason, library: s.library, commit: s.target.commit, suite: s.suite,
      counts: null, precision: null, gaps: [HOSTILE.gap], seal: null, kit_version: HOSTILE.kit,
      coverage: { cross_backend: "unavailable", partner: "openfhe", reason: HOSTILE.coverageReason },
      started_at: new Date(job.created).toISOString(), finished_at: new Date().toISOString(), duration_s: 1 };
  }
  if (verdict === "REFUSED") {
    return { job_id: job.id, verdict, reason: "commit not found at the URL", library: s.library, commit: s.target.commit,
      suite: s.suite, counts: null, precision: null, gaps: [], seal: null, kit_version: "0.1.0",
      started_at: new Date(job.created).toISOString(), finished_at: new Date().toISOString(), duration_s: 1 };
  }
  const fail = verdict === "FAIL";
  const errored = verdict === "ERROR";
  return {
    job_id: job.id,
    verdict,
    library: s.library,
    library_version: "v6.2.0", // SPEC v0.3: detected by the fetch stage
    commit: s.target.commit,
    suite: s.suite,
    counts: errored ? { cases: 0, within: 0, beyond: 0, errors: 1 } : { cases: 48, within: fail ? 45 : 48, beyond: fail ? 3 : 0, errors: 0 },
    precision: errored ? { min_bits: null, median_bits: null } : { min_bits: fail ? 7.9 : 19.4, median_bits: 23.1 },
    gaps: verdict === "PASS" ? ["scalar-mul scale tracking not exercised at level 0 (informational)"] : [],
    seal: { plan_sha256: "a".repeat(64), expected_index_sha256: "b".repeat(64),
      // internal fields: a conforming API strips them (SPEC v0.1 section 2); the "internal" scenario leaks them on
      // purpose so the tests can prove the Action drops them anyway
      ...(job.scenario === "internal" ? { seal_commit: "c".repeat(40) } : {}) },
    // SPEC v0.4: the partner adds coverage but never decides the verdict; the fail scenario reports it unavailable
    coverage: fail
      ? { cross_backend: "unavailable", partner: "openfhe", reason: "partner build failed" }
      : { cross_backend: "done", partner: s.library === "openfhe" ? "lattigo" : "openfhe", reason: "" },
    // SPEC v0.14: which adapter ran and at which conformance level. A repository that ships its own gets its own
    // name and, here, level 1 (final outputs only); one of ours reports level 2 (full trace).
    adapter: s.library === "custom"
      ? { name: "acme-chip", level: 1, timeout_s: 600 }
      : { name: s.library, level: 2, timeout_s: 600 },
    kit_version: "0.1.0",
    ...(job.scenario === "internal" ? { kit_commit: "167340203f220e05f8b54641d818a18cf7096e27", worker_host: "internal-host-7" } : {}),
    started_at: new Date(job.created).toISOString(),
    finished_at: new Date().toISOString(),
    duration_s: 1,
  };
}

function view(job, origin) {
  job.polls += 1;
  const base = { job_id: job.id, status: "queued", result: null, report_url: null };
  if (job.scenario === "slow") return { ...base, status: job.polls < 2 ? "queued" : "running" };
  if (job.polls < 2) return { ...base, status: "running" };
  const verdict = { pass: "PASS", flaky: "PASS", internal: "PASS", fail: "FAIL", error: "ERROR", refused: "REFUSED", hostile: "REFUSED" }[job.scenario];
  const exp = Math.floor(Date.now() / 1000) + 86400;
  return {
    job_id: job.id,
    status: verdict === "ERROR" ? "error" : "done",
    result: resultFor(job, verdict),
    // like part A: a signed link on the API's own origin
    report_url: job.scenario === "hostile" ? HOSTILE.reportUrl : `${origin}/v1/reports/${job.id}/REPORT.html?exp=${exp}&sig=${"0".repeat(64)}`,
  };
}

function send(res, code, body, headers = {}) {
  res.writeHead(code, { "Content-Type": "application/json", ...headers });
  res.end(JSON.stringify(body));
  return code;
}

function log(entry) {
  if (LOG) appendFileSync(LOG, JSON.stringify({ t: new Date().toISOString(), ...entry }) + "\n");
}

const server = createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => {
    raw += c;
    if (raw.length > 16384) req.destroy();
  });
  req.on("end", () => {
    const url = new URL(req.url, "http://stub");
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    const scenario = scenarioOf(token);
    let code;
    if (req.method === "GET" && url.pathname === "/v1/health") {
      code = send(res, 200, { ok: true });
    } else if (!scenario) {
      code = send(res, 401, { error: "invalid token" });
    } else if (req.method === "POST" && url.pathname === "/v1/jobs") {
      const f = flaky.get(token) || { postFailed: false, getFailed: false };
      flaky.set(token, f);
      if (scenario === "flaky" && !f.postFailed) {
        f.postFailed = true;
        code = send(res, 503, { error: "temporarily unavailable" }, { "Retry-After": "1" });
      } else {
        let body = null;
        try { body = JSON.parse(raw); } catch { body = null; }
        const bad = validateSpec(body);
        if (bad) {
          code = send(res, 400, { error: bad });
        } else {
          const key = tokenHash(token) + JSON.stringify([body.library, body.target.commit, body.suite, body.options]);
          let id = idem.get(key);
          if (id) {
            code = send(res, 200, { job_id: id, status: "queued" }); // SPEC v0.1: a replay returns 200
          } else {
            id = newJobId();
            idem.set(key, id);
            jobs.set(id, { id, owner: token, scenario, spec: body, polls: 0, created: Date.now() });
            // the hostile scenario also tries to inject a workflow command through the submit status
            code = send(res, 202, { job_id: id, status: scenario === "hostile" ? "queued\n::error::injected-by-server" : "queued" });
          }
        }
      }
    } else if (req.method === "GET" && url.pathname.startsWith("/v1/jobs/")) {
      const id = url.pathname.slice("/v1/jobs/".length);
      const job = jobs.get(id);
      const f = flaky.get(token) || {};
      if (!job || job.owner !== token) {
        code = send(res, 404, { error: "not found" }); // each customer sees only its own jobs
      } else if (scenario === "flaky" && !f.getFailed) {
        f.getFailed = true;
        code = send(res, 429, { error: "rate limited" }, { "Retry-After": "1" });
      } else {
        code = send(res, 200, view(job, `http://${req.headers.host}`));
      }
    } else {
      code = send(res, 404, { error: "not found" });
    }
    let bodyKeys = null;
    try { bodyKeys = req.method === "POST" ? Object.keys(JSON.parse(raw)) : null; } catch { bodyKeys = null; }
    log({ method: req.method, path: url.pathname, status: code, scenario, body_keys: bodyKeys, token_sha256_12: token ? tokenHash(token) : null });
  });
});

server.listen(PORT, "127.0.0.1", () => {
  process.stdout.write(`stub-api listening on http://127.0.0.1:${PORT}\n`);
});
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => server.close(() => process.exit(0)));

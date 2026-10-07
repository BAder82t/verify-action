// Unit and integration tests for client/src/verify.mjs. Run: node --test client/test/
// The integration cases start the stub API on a random local port and drive run() with a virtual clock, so the
// timeout arm takes milliseconds instead of minutes.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { DEFAULT_API_URL } from "../src/service-url.mjs";
import { conformance, customerView, decide, escapeCommand, jobBody, md, nextDelayMs, parseApiUrl, ranSomething, readConfig, renderSummary, run, safeReportUrl, scrub } from "../src/verify.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SHA = "0123456789abcdef0123456789abcdef01234567";
const nonce = () => Math.random().toString(36).slice(2, 12).padEnd(10, "x");

function baseEnv(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "vbv-test-"));
  const summary = join(dir, "summary.md");
  const output = join(dir, "output.txt");
  writeFileSync(summary, "");
  writeFileSync(output, "");
  return {
    dir, summary, output,
    // the minimal form (SPEC v0.3): only a token; the tests reach the stub through a workflow-level VBV_API_URL
    env: {
      VBV_TIMEOUT_SECONDS: "600", VBV_POLL_INTERVAL_SECONDS: "1",
      GITHUB_SHA: SHA, GITHUB_REPOSITORY: "acme/fhe-lib", GITHUB_REF: "refs/heads/main",
      GITHUB_SERVER_URL: "https://github.com", GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: output, RUNNER_TEMP: dir,
      ...extra,
    },
  };
}

function fakeIO() {
  let t = 1_700_000_000_000;
  const lines = [];
  return {
    lines,
    io: {
      log: (m) => lines.push(m), now: () => t, sleep: async (ms) => { t += ms; },
      mkdir: (d) => mkdirSync(d, { recursive: true }),
      writeFile: (p, s) => writeFileSync(p, s), append: (p, s) => writeFileSync(p, readFileSync(p, "utf8") + s),
      readFile: (p) => readFileSync(p, "utf8"), tmpdir: () => tmpdir(),
    },
  };
}



describe("pure helpers", () => {
  it("accepts https and loopback http, refuses plain http elsewhere", () => {
    assert.equal(parseApiUrl("https://verify.example.com/"), "https://verify.example.com");
    assert.equal(parseApiUrl("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
    assert.equal(parseApiUrl("http://localhost:1/api/"), "http://localhost:1/api");
    assert.throws(() => parseApiUrl("http://verify.example.com"), /https/);
    assert.throws(() => parseApiUrl("http://127.0.0.1.nip.io"), /https/);
    assert.throws(() => parseApiUrl("https://user:pw@verify.example.com"), /credentials/);
    assert.throws(() => parseApiUrl("not a url"), /valid URL/);
  });

  it("decides per fail-on, failing closed on anything unknown", () => {
    assert.equal(decide("PASS", "ERROR").pass, true);
    assert.equal(decide("FAIL", "FAIL").pass, false);
    assert.equal(decide("FAIL", "ERROR").pass, false);
    assert.equal(decide("ERROR", "ERROR").pass, false);
    assert.equal(decide("ERROR", "FAIL").pass, true);
    assert.equal(decide("REFUSED", "ERROR").pass, false);
    assert.equal(decide("REFUSED", "FAIL").pass, true);
    assert.equal(decide("GAP", "FAIL").pass, false);
    assert.equal(decide(undefined, "FAIL").pass, false);
  });

  it("backs off 1.5x per attempt, caps at 60 s, honours Retry-After", () => {
    const mid = () => 0.5;
    assert.equal(nextDelayMs(0, 10, 0, mid), 10000);
    assert.equal(nextDelayMs(1, 10, 0, mid), 15000);
    assert.equal(nextDelayMs(20, 10, 0, mid), 60000);
    assert.equal(nextDelayMs(0, 1, 30, mid), 30000);
  });

  it("scrubs the token and control characters", () => {
    assert.equal(scrub("bad token vbv_SECRET123 here\n\x1b[31m", "vbv_SECRET123"), "bad token *** here [31m");
    assert.equal(escapeCommand("50%\nnext"), "50%25%0Anext");
  });

  it("escapes server text in the summary", () => {
    assert.equal(md("a|b<script>"), "a\\|b&lt;script&gt;");
    assert.equal(md("x".repeat(250)).length, 203);
    assert.doesNotMatch(md("[a](javascript:x)"), /\]\(/);
    assert.equal(safeReportUrl("https://api.example.com/v1/reports/j/REPORT.html?exp=1&sig=ab", "https://api.example.com"),
      "https://api.example.com/v1/reports/j/REPORT.html?exp=1&sig=ab");
    assert.equal(safeReportUrl("https://evil.example/v1/reports/x", "https://api.example.com"), null);
    assert.equal(safeReportUrl("https://api.example.com/a) [x](javascript:1", "https://api.example.com"), null);
    assert.equal(safeReportUrl("javascript:alert(1)", "https://api.example.com"), null);
    const s = renderSummary({ verdict: "PASS", pass: true, failOn: "ERROR", result: { gaps: ["x|y"] }, reportUrl: null });
    assert.match(s, /x\\\|y/);
  });

  it("keeps only the customer-visible result fields (SPEC v0.1 section 2)", () => {
    const v = customerView({ job_id: "j_X", verdict: "PASS", kit_commit: "k", kit_version: "0.1.0", extra: 1,
      seal: { plan_sha256: "p", expected_index_sha256: "e", seal_commit: "s" }, counts: { cases: 1, secret: 2 } });
    assert.deepEqual(v, { job_id: "j_X", verdict: "PASS", kit_version: "0.1.0",
      seal: { plan_sha256: "p", expected_index_sha256: "e" }, counts: { cases: 1 } });
    const refused = customerView({ job_id: "j_X", verdict: "REFUSED", counts: null, reason: "commit not found at the URL" });
    assert.deepEqual(refused, { job_id: "j_X", verdict: "REFUSED", counts: null, reason: "commit not found at the URL" });
    assert.match(renderSummary({ verdict: "REFUSED", pass: false, failOn: "ERROR", result: refused }), /\| Reason \| commit not found at the URL \|/);
    assert.equal(customerView(null), null);
    assert.equal(customerView([1]), null);
  });

  it("states the conformance level, and never lets a level 1 PASS read like a level 2 one (SPEC v0.14)", () => {
    const summary = (adapter, verdict = "PASS") =>
      renderSummary({ verdict, pass: verdict === "PASS", failOn: "FAIL", result: { verdict, adapter }, reportUrl: null });

    const two = summary({ name: "lattigo", level: 2, timeout_s: 600 });
    assert.match(two, /\| Conformance \| Level 2 - full trace: final outputs, per-operation values and declared metadata \(adapter: lattigo\) \|/);
    assert.doesNotMatch(two, /Level 1 conformance:/);

    const one = summary({ name: "acme-chip", level: 1, timeout_s: 600 });
    assert.match(one, /\| Conformance \| Level 1 - final outputs only \(adapter: acme-chip\) \|/);
    assert.match(one, /> Level 1 conformance: this PASS covers each program's final outputs only\./);
    assert.notEqual(one, two);

    // a FAIL needs no caveat: the caveat is about how much a PASS is worth
    assert.doesNotMatch(summary({ name: "acme-chip", level: 1, timeout_s: 600 }, "FAIL"), /Level 1 conformance:/);

    // absent or unrecognised: reported as such, never quietly rendered as the stronger level
    for (const bad of [undefined, null, {}, [1], "level 2", { name: "x", level: 3, timeout_s: 1 }, { name: "x", level: "2", timeout_s: 1 }]) {
      assert.match(summary(bad), /\| Conformance \| not reported/, JSON.stringify(bad));
      assert.doesNotMatch(summary(bad), /Level [12] -/, JSON.stringify(bad));
      assert.doesNotMatch(summary(bad), /Level 1 conformance:/, JSON.stringify(bad));
    }
    assert.deepEqual(conformance({ adapter: { name: "acme-chip", level: 1, timeout_s: 600 } }),
      { level: 1, label: "Level 1 - final outputs only", name: "acme-chip" });
    assert.equal(conformance({ adapter: { name: "x", level: 2, timeout_s: 1 } }).label.includes("full trace"), true);
    assert.equal(conformance(null).level, null);

    // a hostile adapter name cannot break the table or inject markup
    assert.match(summary({ name: "a|b<script>", level: 2, timeout_s: 1 }), /adapter: a\\\|b&lt;script&gt;/);

    // the adapter survives customerView, so it also reaches the result.json artifact
    assert.deepEqual(customerView({ job_id: "j_X", adapter: { name: "acme-chip", level: 1, timeout_s: 600, secret: 1 } }).adapter,
      { name: "acme-chip", level: 1, timeout_s: 600 });
  });

  it("accepts library: custom and sends it (SPEC v0.14)", () => {
    const { env } = baseEnv({ VBV_API_URL: "https://x.example", VBV_TOKEN: "t0k3n-abcdef" });
    assert.equal(jobBody(readConfig({ ...env, VBV_LIBRARY: "custom" })).library, "custom");
    assert.equal(jobBody(readConfig({ ...env, VBV_LIBRARY: " CUSTOM " })).library, "custom");
    assert.throws(() => readConfig({ ...env, VBV_LIBRARY: "customer" }), /auto, lattigo, openfhe or custom/);
  });

  it("needs only a token: library, suite, options are auto and omitted; fail-on defaults to FAIL", () => {
    const { env } = baseEnv({ VBV_API_URL: "https://x.example", VBV_TOKEN: "t0k3n-abcdef" });
    const cfg = readConfig(env);
    assert.equal(cfg.failOn, "FAIL");
    assert.deepEqual(Object.keys(jobBody(cfg)), ["target"]);
    assert.deepEqual(jobBody(cfg).target, { kind: "git", url: "https://github.com/acme/fhe-lib.git", ref: "refs/heads/main", commit: SHA });
    const chosen = jobBody(readConfig({ ...env, VBV_LIBRARY: "openfhe", VBV_SUITE: "ckks-core-v0", VBV_JOB_TIMEOUT_SECONDS: "600" }));
    assert.deepEqual(chosen, { target: jobBody(cfg).target, library: "openfhe", suite: "ckks-core-v0", options: { timeout_s: 600 } });
  });

  it("resolves api-url: input, then VBV_API_URL, then the built-in default (https, never a placeholder)", () => {
    const { env } = baseEnv({ VBV_TOKEN: "t0k3n-abcdef" });
    assert.equal(readConfig(env).apiUrl, parseApiUrl(DEFAULT_API_URL));
    assert.match(DEFAULT_API_URL, /^https:\/\//);
    assert.ok(!new URL(DEFAULT_API_URL).hostname.endsWith(".invalid"));
    assert.equal(readConfig({ ...env, VBV_API_URL: "https://env.example" }).apiUrl, "https://env.example");
    assert.equal(readConfig({ ...env, VBV_API_URL: "https://env.example", VBV_INPUT_API_URL: "https://input.example" }).apiUrl, "https://input.example");
  });

  it("validates configuration before any request", () => {
    const { env } = baseEnv({ VBV_API_URL: "https://x.example", VBV_TOKEN: "t0k3n-abcdef" });
    assert.equal(readConfig(env).target.url, "https://github.com/acme/fhe-lib.git");
    assert.throws(() => readConfig({ ...env, VBV_TOKEN: "" }), /token/);
    assert.throws(() => readConfig({ ...env, VBV_TOKEN: "has space" }), /malformed/);
    assert.throws(() => readConfig({ ...env, VBV_LIBRARY: "seal" }), /library/);
    assert.throws(() => readConfig({ ...env, VBV_FAIL_ON: "WARN" }), /fail-on/);
    assert.throws(() => readConfig({ ...env, GITHUB_SHA: "abc" }), /GITHUB_SHA/);
    assert.throws(() => readConfig({ ...env, VBV_TIMEOUT_SECONDS: "1" }), /timeout-seconds/);
  });

  it("ranSomething (main.mjs's last-line guard, SPEC v0.11 hardening): false only when run() produced neither a verdict nor a status", () => {
    // This is the path a skipped run() takes: main.mjs's .then() receives whatever run() resolved
    // to, and an entry-point bug that made run() never execute at all would never even reach this
    // callback -- so this test's "skipped" case is the guard's own worst case: run() DID execute
    // but produced nothing meaningful (its earliest possible exit, e.g. before any verdict).
    assert.equal(ranSomething({ verdict: "", status: "", decision: "fail" }), false);
    assert.equal(ranSomething(null), false);
    assert.equal(ranSomething(undefined), false);
    assert.equal(ranSomething({}), false);
    // A verdict or a status means the job actually ran, whatever the outcome -- including a
    // failing one; fail-on nuance is action.yml's "Enforce the decision" step's job, not this
    // guard's.
    assert.equal(ranSomething({ verdict: "FAIL", status: "done", decision: "fail" }), true);
    assert.equal(ranSomething({ verdict: "", status: "error", decision: "fail" }), true);
    assert.equal(ranSomething({ verdict: "PASS", status: "done", decision: "pass" }), true);
  });
});

describe("against the stub API", () => {
  let proc; let port; let logFile;
  before(async () => {
    port = 20000 + Math.floor(Math.random() * 20000);
    logFile = join(mkdtempSync(join(tmpdir(), "vbv-stub-")), "requests.jsonl");
    proc = spawn(process.execPath, [join(HERE, "stub-api.mjs"), "--port", String(port), "--log", logFile], { stdio: ["ignore", "pipe", "inherit"] });
    await new Promise((resolve, reject) => {
      proc.stdout.on("data", (d) => (String(d).includes("listening") ? resolve() : null));
      proc.on("exit", (c) => reject(new Error("stub exited " + c)));
    });
  });
  after(() => proc && proc.kill());

  async function arm(scenario, extra = {}) {
    const token = scenario ? `vbvtest_${scenario}_${nonce()}` : `revoked_${nonce()}`;
    const b = baseEnv({ VBV_API_URL: `http://127.0.0.1:${port}`, VBV_TOKEN: token, ...extra });
    const f = fakeIO();
    const outputs = await run(b.env, f.io);
    const summary = readFileSync(b.summary, "utf8");
    const all = f.lines.join("\n") + summary + readFileSync(b.output, "utf8") +
      (outputs["result-path"] && existsSync(outputs["result-path"]) ? readFileSync(outputs["result-path"], "utf8") : "");
    return { token, outputs, summary, lines: f.lines, all, b };
  }

  it("PASS (minimal form): passes, sends only the target, shows the detected library, never prints the token", async () => {
    const r = await arm("pass");
    const posts = readFileSync(logFile, "utf8").split("\n").filter((l) => l.includes('"method":"POST"')).map((l) => JSON.parse(l));
    assert.deepEqual(posts[posts.length - 1].body_keys, ["target"]);
    assert.match(r.summary, /\| Library \| lattigo \(detected\) \|/);
    assert.match(r.summary, /\| Library version \| v6\.2\.0 \|/);
    assert.match(r.summary, /\| Cross-backend coverage \| done \(partner: openfhe\) \|/);
    assert.match(r.summary, /\| Conformance \| Level 2 - full trace: .* \(adapter: lattigo\) \|/);
    assert.doesNotMatch(r.summary, /Level 1 conformance:/);
    assert.deepEqual(JSON.parse(readFileSync(r.outputs["result-path"], "utf8")).coverage, { cross_backend: "done", partner: "openfhe", reason: "" });
    assert.deepEqual(JSON.parse(readFileSync(r.outputs["result-path"], "utf8")).adapter, { name: "lattigo", level: 2, timeout_s: 600 });
    assert.equal(r.outputs.decision, "pass");
    assert.equal(r.outputs.verdict, "PASS");
    assert.match(r.outputs["job-id"], /^j_[0-9A-Z]{26}$/);
    const result = JSON.parse(readFileSync(r.outputs["result-path"], "utf8"));
    assert.equal(result.verdict, "PASS");
    assert.equal(result.commit, SHA);
    assert.match(r.summary, /VaultBytes Verify: PASS/);
    assert.match(r.summary, /\| Cases \| 48 \|/);
    assert.match(r.summary, /Precision, min bits \| 19\.4/);
    assert.match(r.summary, /\| Kit version \| 0\.1\.0 \|/);
    assert.ok(!r.all.includes(r.token), "token leaked");
    assert.ok(!r.lines.some((l) => l.startsWith("::add-mask::")), "no mask command outside Actions");
  });

  it("a PASS through the repository's own adapter says which level it is (SPEC v0.14)", async () => {
    const r = await arm("pass", { VBV_LIBRARY: "custom" });
    const posts = readFileSync(logFile, "utf8").split("\n").filter((l) => l.includes('"method":"POST"')).map((l) => JSON.parse(l));
    assert.ok(posts[posts.length - 1].body_keys.includes("library"));
    assert.equal(r.outputs.verdict, "PASS");
    assert.equal(r.outputs.decision, "pass");
    assert.match(r.summary, /\| Library \| custom \|/);
    assert.match(r.summary, /\| Conformance \| Level 1 - final outputs only \(adapter: acme-chip\) \|/);
    assert.match(r.summary, /> Level 1 conformance: this PASS covers each program's final outputs only\./);
    assert.deepEqual(JSON.parse(readFileSync(r.outputs["result-path"], "utf8")).adapter, { name: "acme-chip", level: 1, timeout_s: 600 });
    assert.ok(!r.all.includes(r.token), "token leaked");
  });

  it("FAIL verdict fails the check under either fail-on; an unavailable partner is stated plainly", async () => {
    for (const failOn of ["ERROR", "FAIL"]) {
      const r = await arm("fail", { VBV_FAIL_ON: failOn });
      assert.match(r.summary, /\| Cross-backend coverage \| cross-backend comparison not performed \(partner build failed\) \|/);
      assert.equal(r.outputs.decision, "fail");
      assert.equal(r.outputs.verdict, "FAIL");
      assert.ok(r.lines.some((l) => l.startsWith("::error ")));
      assert.ok(!r.all.includes(r.token));
    }
  });

  it("ERROR verdict warns by default (fail-on FAIL) and fails under fail-on ERROR", async () => {
    const strict = await arm("error", { VBV_FAIL_ON: "ERROR" });
    assert.equal(strict.outputs.decision, "fail");
    assert.equal(strict.outputs.status, "error");
    const byDefault = await arm("error");
    assert.equal(byDefault.outputs.decision, "pass");
    assert.ok(byDefault.lines.some((l) => l.startsWith("::warning ")));
  });

  it("REFUSED (SPEC v0.2) fails under fail-on ERROR, warns by default, and shows the reason", async () => {
    const strict = await arm("refused", { VBV_FAIL_ON: "ERROR" });
    assert.equal(strict.outputs.verdict, "REFUSED");
    assert.equal(strict.outputs.decision, "fail");
    assert.match(strict.summary, /\| Reason \| commit not found at the URL \|/);
    assert.match(strict.summary, /\| Cases \| n\/a \|/);
    const byDefault = await arm("refused");
    assert.equal(byDefault.outputs.decision, "pass");
  });

  it("renders hostile server text inert (HTML, Markdown links, table pipes, bad report URL)", async () => {
    const r = await arm("hostile", { GITHUB_EVENT_PATH: (() => {
      const ev = join(mkdtempSync(join(tmpdir(), "vbv-ev-")), "event.json");
      writeFileSync(ev, JSON.stringify({ repository: { private: true } })); // links would be shown if safe
      return ev;
    })() });
    // positive control: the stub really sends the payloads
    const raw = await (await fetch(`http://127.0.0.1:${port}/v1/jobs/${r.outputs["job-id"]}`,
      { headers: { Authorization: `Bearer ${r.token}` } })).text();
    assert.ok(raw.includes("<img src=x onerror=alert(1)>") && raw.includes("](javascript:alert(3)"));
    const text = r.summary + r.lines.join("\n");
    assert.ok(raw.includes("onerror=alert(4)"), "stub sends the hostile coverage reason");
    assert.match(r.summary, /cross-backend comparison not performed \(&lt;img src=y onerror=alert\\\(4\\\)&gt; \\\| /);
    assert.ok(!r.lines.some((l) => l.includes("injected-by-server")), "submit status must not reach the log");
    assert.ok(r.lines.some((l) => /^Job j_[0-9A-Z]{26} accepted \(status: queued\)$/.test(l)));
    // positive control: the stub's submit answer really carries the injection attempt
    const post = await (await fetch(`http://127.0.0.1:${port}/v1/jobs`, { method: "POST",
      headers: { Authorization: `Bearer vbvtest_hostile_${nonce()}`, "Content-Type": "application/json" },
      body: JSON.stringify({ target: { kind: "git", url: "https://github.com/a/b.git", ref: "", commit: SHA } }) })).text();
    assert.match(post, /injected-by-server/);
    for (const bad of ["<img", "<script", "<b>", "](javascript:", "](https://evil", "![img]", "evil.example/r)"]) {
      assert.ok(!text.includes(bad), `summary or log contains raw ${bad}`);
    }
    const reasonRow = r.summary.split("\n").find((l) => l.startsWith("| Reason |"));
    assert.equal(reasonRow.replace(/\\\|/g, "").split("|").length, 4, "reason must stay in one table cell");
    assert.match(r.summary, /not a plain URL on the API's origin; it is not shown/);
    assert.equal(r.outputs["report-url"], "");
    assert.equal(r.outputs.decision, "pass"); // REFUSED under the default fail-on FAIL: a warning, not a failure
  });

  it("a rejected token fails clearly and does not echo it", async () => {
    const r = await arm(null);
    assert.equal(r.outputs.decision, "fail");
    assert.match(r.outputs.reason, /^auth: authentication failed \(HTTP 401\)/);
    assert.equal(r.outputs["result-path"], "");
    assert.ok(!r.all.includes(r.token));
  });

  it("times out while the job keeps running", async () => {
    const r = await arm("slow", { VBV_TIMEOUT_SECONDS: "30" });
    assert.equal(r.outputs.decision, "fail");
    assert.match(r.outputs.reason, /^timeout: timed out after 30 s/);
    assert.equal(r.outputs.status, "running");
  });

  it("retries 503 and 429 with Retry-After, then passes", async () => {
    const r = await arm("flaky");
    assert.equal(r.outputs.decision, "pass");
    assert.ok(r.lines.some((l) => /HTTP 503/.test(l)));
    assert.ok(r.lines.some((l) => /HTTP 429/.test(l)));
  });

  it("refuses plain http to a remote host before sending anything", async () => {
    const before = existsSync(logFile) ? readFileSync(logFile, "utf8").length : 0;
    const b = baseEnv({ VBV_API_URL: "http://verify.example.com", VBV_TOKEN: `vbvtest_pass_${nonce()}` });
    const f = fakeIO();
    const outputs = await run(b.env, f.io);
    assert.equal(outputs.decision, "fail");
    assert.match(outputs.reason, /^config: .*https/);
    assert.equal(existsSync(logFile) ? readFileSync(logFile, "utf8").length : 0, before);
  });

  it("inside Actions emits exactly one mask command and no other copy of the token", async () => {
    const r = await arm("pass", { GITHUB_ACTIONS: "true" });
    const masked = r.lines.filter((l) => l === `::add-mask::${r.token}`);
    assert.equal(masked.length, 1);
    const rest = r.all.split("\n").filter((l) => l !== `::add-mask::${r.token}`).join("\n");
    assert.ok(!rest.includes(r.token));
  });

  it("shows the report link only for a private repository in auto mode", async () => {
    const ev = join(mkdtempSync(join(tmpdir(), "vbv-ev-")), "event.json");
    writeFileSync(ev, JSON.stringify({ repository: { private: false } }));
    const pub = await arm("pass", { GITHUB_EVENT_PATH: ev });
    assert.doesNotMatch(pub.summary, /\/v1\/reports\//);
    assert.equal(pub.outputs["report-url"], "");
    writeFileSync(ev, JSON.stringify({ repository: { private: true } }));
    const priv = await arm("pass", { GITHUB_EVENT_PATH: ev });
    assert.match(priv.summary, /\[REPORT\.html\]\(http:\/\/127\.0\.0\.1:\d+\/v1\/reports\/j_[0-9A-Z]{26}\/REPORT\.html\?exp=/);
    assert.ok(!readFileSync(priv.outputs["result-path"], "utf8").includes("sig="), "signed URL must not be in result.json");
  });

  it("drops internal result fields even if the API returns them", async () => {
    const r = await arm("internal");
    assert.equal(r.outputs.decision, "pass");
    const text = readFileSync(r.outputs["result-path"], "utf8");
    const result = JSON.parse(text);
    assert.equal(result.kit_version, "0.1.0");
    assert.ok(!("kit_commit" in result) && !("worker_host" in result) && !("seal_commit" in result.seal));
    assert.doesNotMatch(r.summary + text, /167340203f|internal-host-7|c{40}/);
    // positive control: the stub really does send the internal fields, so the absence above is not vacuous
    const raw = await (await fetch(`http://127.0.0.1:${port}/v1/jobs/${r.outputs["job-id"]}`,
      { headers: { Authorization: `Bearer ${r.token}` } })).text();
    assert.match(raw, /"kit_commit":"167340203f/);
    assert.match(raw, /"seal_commit":"c{40}"/);
  });

  it("a replayed submission (HTTP 200) is followed like a new one", async () => {
    const token = `vbvtest_pass_${nonce()}`;
    const first = await arm("pass", { VBV_TOKEN: token });
    const again = await arm("pass", { VBV_TOKEN: token });
    assert.equal(again.outputs["job-id"], first.outputs["job-id"]);
    assert.equal(again.outputs.decision, "pass");
  });

  it("the stub log never contains a token", () => {
    const text = readFileSync(logFile, "utf8");
    assert.ok(text.length > 0);
    assert.doesNotMatch(text, /vbvtest_/);
  });

  it("main.mjs still submits when the client directory is only reached through a symlink (SPEC v0.11 hardening)", async () => {
    // Reproduces the shape of the real bug (not a synthetic string mismatch): act's local-action
    // staging placed the whole client/ directory behind a symlinked ancestor path
    // (/var/run/act/... where /var/run -> /run), which broke the old "is this the entry module"
    // string comparison and made run() silently never execute. main.mjs has no such comparison
    // any more -- this proves it by actually invoking it as a real child process through an
    // equivalent symlink and checking that a real job was submitted, not just that main.mjs
    // exited 0 (which the old, broken code also did).
    const linkParent = mkdtempSync(join(tmpdir(), "vbv-symlink-"));
    const link = join(linkParent, "client-via-symlink");
    symlinkSync(join(HERE, ".."), link); // HERE = client/test, so ".." is the real client/ directory
    const b = baseEnv({ VBV_API_URL: `http://127.0.0.1:${port}`, VBV_TOKEN: `vbvtest_pass_${nonce()}` });
    const code = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [join(link, "src", "main.mjs")], { env: { ...process.env, ...b.env } });
      child.on("exit", resolve);
      child.on("error", reject);
    });
    assert.equal(code, 0, "main.mjs via a symlinked directory must still run and exit 0 for a PASS");
    const outputs = Object.fromEntries(readFileSync(b.output, "utf8").trim().split("\n").filter(Boolean)
      .map((l) => { const i = l.indexOf("="); return [l.slice(0, i), l.slice(i + 1)]; }));
    assert.equal(outputs.verdict, "PASS", "the job must actually have been submitted and completed, not silently skipped");
    assert.match(outputs["job-id"], /^j_[0-9A-Z]{26}$/);
  });
});

// Regression tests for the Action's own supply-chain posture. Each one pins a property the README and SECURITY.md
// state, so a later change cannot silently weaken it.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readConfig, UNSAFE_EVENTS } from "../src/verify.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = "0123456789abcdef0123456789abcdef01234567";
const base = (extra = {}) => ({
  VBV_TOKEN: "t0k3n-abcdef", VBV_API_URL: "https://api.example",
  GITHUB_SHA: SHA, GITHUB_REPOSITORY: "acme/fhe-lib", GITHUB_REF: "refs/heads/main", ...extra,
});

describe("untrusted events", () => {
  for (const ev of ["pull_request_target", "workflow_run"]) {
    it(`refuses the ${ev} event before it reads the token`, () => {
      assert.throws(() => readConfig(base({ GITHUB_EVENT_NAME: ev })), new RegExp(`refusing to run on the '${ev}' event`));
      // refused even with no token present: the event check comes first, so the token is never inspected
      assert.throws(() => readConfig(base({ GITHUB_EVENT_NAME: ev, VBV_TOKEN: "" })), /refusing to run/);
    });
  }
  it("lists exactly those two events as unsafe", () => {
    assert.deepEqual([...UNSAFE_EVENTS].sort(), ["pull_request_target", "workflow_run"]);
  });
  for (const ev of ["push", "pull_request", "workflow_dispatch", "schedule", ""]) {
    it(`still runs on '${ev || "(unset)"}'`, () => {
      assert.equal(readConfig(base({ GITHUB_EVENT_NAME: ev })).token, "t0k3n-abcdef");
    });
  }
  it("explains a missing token on a pull request, without echoing anything secret", () => {
    assert.throws(() => readConfig(base({ GITHUB_EVENT_NAME: "pull_request", VBV_TOKEN: "" })), /fork does not receive repository secrets/);
  });
});

describe("network behaviour matches what the README documents", () => {
  const src = readFileSync(join(ROOT, "src", "verify.mjs"), "utf8");
  it("makes its network calls through one request function only", () => {
    assert.equal((src.match(/\bfetch\(/g) || []).length, 1);
  });
  it("never follows a redirect while carrying the bearer token", () => {
    assert.match(src, /redirect: "error"/);
  });
  it("calls only the two documented endpoints", () => {
    const paths = new Set([...src.matchAll(/["`](\/v1\/[^"`$]*)/g)].map((m) => m[1]));
    assert.deepEqual([...paths].sort(), ["/v1/jobs", "/v1/jobs/"]);
  });
  it("has no runtime dependencies", () => {
    assert.ok(!existsSync(join(ROOT, "package.json")) || !("dependencies" in JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"))));
    assert.ok(!/from "(?!node:|\.)[^"]+"/.test(src), "an import that is neither node: nor relative");
  });
});

describe("workflows and action metadata", () => {
  const files = ["action.yml", ...(existsSync(join(ROOT, ".github", "workflows")) ? readdirSync(join(ROOT, ".github", "workflows")).map((f) => `.github/workflows/${f}`) : [])];
  const text = (f) => readFileSync(join(ROOT, f), "utf8");
  it("pins every third-party action to a full commit SHA", () => {
    for (const f of files) {
      for (const m of text(f).matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm)) {
        const ref = m[1];
        if (ref.startsWith("./")) continue;
        assert.match(ref, /@[0-9a-f]{40}$/, `${f}: '${ref}' is not pinned to a commit SHA`);
      }
    }
  });
  it("gives every workflow an explicit read-only default token", () => {
    for (const f of files.filter((x) => x.startsWith(".github/workflows/"))) {
      assert.match(text(f), /^permissions:\s*\n\s+contents:\s*read\s*$/m, `${f}: top-level 'permissions: contents: read' missing`);
    }
  });
  it("uses no pull_request_target or workflow_run trigger", () => {
    for (const f of files.filter((x) => x.startsWith(".github/workflows/"))) {
      assert.ok(!/pull_request_target|workflow_run/.test(text(f).replace(/#.*$/gm, "")), f);
    }
  });
  it("never interpolates an event field straight into a shell step", () => {
    for (const f of files.filter((x) => x.startsWith(".github/workflows/"))) {
      const lines = text(f).split("\n");
      lines.forEach((line, i) => {
        const m = line.match(/^(\s*)-?\s*run:\s*(.*)$/);
        if (!m) return;
        const indent = m[1].length;
        let body = m[2];
        for (let j = i + 1; j < lines.length; j++) {
          const l = lines[j];
          if (l.trim() !== "" && l.match(/^(\s*)/)[1].length <= indent) break;
          body += "\n" + l;
        }
        assert.ok(!/\$\{\{\s*(github\.(head_ref|ref_name|event\.)|inputs\.)/.test(body), `${f}:${i + 1}: an untrusted value is interpolated into a run step`);
      });
    }
  });
});

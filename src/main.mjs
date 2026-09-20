#!/usr/bin/env node
// The Action's real entry point (action.yml's "Submit and wait" step runs this, not verify.mjs
// directly). It has no other job, so it calls run() UNCONDITIONALLY -- no "is this the entry
// module" heuristic, no import.meta.url comparison. That kind of guard is a fail-open design: if
// the two sides of the comparison ever differ for a reason that has nothing to do with "was this
// imported" -- e.g. a symlink a container's base image resolves on one side and not the other
// (act's local-action staging under /var/run/act/actions/... hit exactly this on
// catthehacker/ubuntu:act-latest, where /var/run is itself a symlink to /run) -- run() silently
// never executes: no error, no output, exit 0, and a check that tested nothing reports green.
// ranSomething() lives in verify.mjs (a pure library, side-effect-free to import) so the test
// suite can exercise the last-line guard directly, without this file's own unconditional call
// ever running as a side effect of importing it.
import { escapeCommand, ranSomething, realIO, run, scrub } from "./verify.mjs";

run(process.env, realIO).then(
  // Last-line guard, independent of action.yml's own "Enforce the decision" step: if nothing was
  // ever produced -- no verdict, no status, meaning the job was never even submitted -- fail
  // closed here too, rather than trust a downstream step alone to catch an upstream no-op.
  // Anything that DID get a verdict (including a legitimate FAIL/ERROR/REFUSED that fail-on turns
  // into a warning) still counts as "ran"; "Enforce the decision" is what applies fail-on.
  (outputs) => process.exit(ranSomething(outputs) ? 0 : 1),
  (e) => {
    process.stdout.write(`::error title=VaultBytes Verify::${escapeCommand(scrub("internal error: " + (e && e.message), process.env.VBV_TOKEN))}\n`);
    process.exit(2);
  },
);

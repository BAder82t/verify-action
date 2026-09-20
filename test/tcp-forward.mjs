// Test plumbing for act on Docker Desktop (macOS): act tells the job container that its artifact server is at
// 127.0.0.1:<port>, but that server listens on the Mac, which a container reaches only as host.docker.internal.
// This forwards 127.0.0.1:<port> inside the job's network namespace to <host>:<port>. Test use only.
//   node client/test/tcp-forward.mjs 34567 host.docker.internal
import { connect, createServer } from "node:net";

const [port, host] = [Number(process.argv[2]), process.argv[3]];
createServer((c) => {
  const u = connect(port, host);
  c.pipe(u).pipe(c);
  const end = () => { c.destroy(); u.destroy(); };
  c.on("error", end); u.on("error", end);
}).listen(port, "127.0.0.1", () => process.stdout.write(`forwarding 127.0.0.1:${port} -> ${host}:${port}\n`));

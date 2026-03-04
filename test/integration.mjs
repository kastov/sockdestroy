/**
 * Integration tests for sockdestroy
 * Requires Linux with CAP_NET_ADMIN (run in privileged Docker container).
 * Runner: node --test test/integration.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { killSockets, hasCapNetAdmin } = require("../lib/index.js");

// EOPNOTSUPP — kernel built without CONFIG_INET_DIAG_DESTROY
// (e.g. Docker Desktop LinuxKit). Detected in pre-flight, used to
// adjust assertions: we still verify `found` but skip `killed` checks.
const EOPNOTSUPP = 95;
let sockDestroySupported = true;

/**
 * Create a TCP server and connect N clients to it.
 * Returns { server, clients, port } — caller must clean up.
 */
async function createConnections(count, host = "127.0.0.1") {
  const server = net.createServer((sock) => sock.resume());

  await new Promise((resolve) => server.listen(0, host, resolve));
  const port = server.address().port;

  const clients = [];
  for (let i = 0; i < count; i++) {
    const sock = new net.Socket();
    await new Promise((resolve, reject) => {
      sock.connect(port, host, resolve);
      sock.once("error", reject);
    });
    clients.push(sock);
  }

  // Let kernel state settle
  await new Promise((r) => setTimeout(r, 100));

  return { server, clients, port };
}

function cleanup(server, clients) {
  for (const c of clients) {
    c.destroy();
  }
  server.close();
}

// ---------------------------------------------------------------------------
// Pre-flight checks
// ---------------------------------------------------------------------------

describe("pre-flight", () => {
  it("is running on Linux", () => {
    assert.equal(process.platform, "linux", "Integration tests require Linux");
  });

  it("has CAP_NET_ADMIN", () => {
    assert.ok(
      hasCapNetAdmin(),
      "Integration tests require CAP_NET_ADMIN (run with --privileged)",
    );
  });

  it("detect SOCK_DESTROY support", async () => {
    // Create one connection and try to kill it to probe kernel support
    const { server, clients } = await createConnections(1);
    try {
      const result = await killSockets({ dst: "127.0.0.1" });
      console.log("    probe result:", JSON.stringify(result));

      if (result.destroyErrno === EOPNOTSUPP) {
        sockDestroySupported = false;
        console.log(
          "    SOCK_DESTROY not supported (EOPNOTSUPP) — kernel lacks CONFIG_INET_DIAG_DESTROY.",
          "\n    Filter/found assertions will still run; kill assertions will be skipped.",
        );
      } else {
        console.log("    SOCK_DESTROY supported");
      }
    } finally {
      cleanup(server, clients);
      await new Promise((r) => setTimeout(r, 100));
    }
  });
});

// ---------------------------------------------------------------------------
// killSockets — real end-to-end
// ---------------------------------------------------------------------------

describe("killSockets e2e (IPv4)", () => {
  it("finds and kills connections by dst", async () => {
    const N = 20;
    const { server, clients } = await createConnections(N);

    try {
      const result = await killSockets({ dst: "127.0.0.1" });
      console.log(`    result: ${JSON.stringify(result)}`);

      // Both client-side (dst=server) and server-side (dst=client) sockets
      // have dst=127.0.0.1 on loopback, so found should be >= 2*N
      assert.ok(
        result.found >= N,
        `expected found >= ${N}, got ${result.found}`,
      );

      if (sockDestroySupported) {
        assert.ok(result.killed >= N, `expected killed >= ${N}, got ${result.killed}`);
        assert.equal(result.destroyErrno, 0);
      }
    } finally {
      cleanup(server, clients);
    }
  });

  it("finds and kills connections by src", async () => {
    const N = 20;
    const { server, clients } = await createConnections(N);

    try {
      const result = await killSockets({ src: "127.0.0.1" });
      console.log(`    result: ${JSON.stringify(result)}`);

      assert.ok(
        result.found >= N,
        `expected found >= ${N}, got ${result.found}`,
      );

      if (sockDestroySupported) {
        assert.ok(result.killed >= N, `expected killed >= ${N}, got ${result.killed}`);
        assert.equal(result.destroyErrno, 0);
      }
    } finally {
      cleanup(server, clients);
    }
  });

  it("finds and kills connections with mode=and", async () => {
    const N = 10;
    const { server, clients } = await createConnections(N);

    try {
      const result = await killSockets({
        src: "127.0.0.1",
        dst: "127.0.0.1",
        mode: "and",
      });
      console.log(`    result: ${JSON.stringify(result)}`);

      assert.ok(
        result.found >= N,
        `expected found >= ${N}, got ${result.found}`,
      );

      if (sockDestroySupported) {
        assert.ok(result.killed >= N, `expected killed >= ${N}, got ${result.killed}`);
        assert.equal(result.destroyErrno, 0);
      }
    } finally {
      cleanup(server, clients);
    }
  });

  it("finds and kills connections with mode=or", async () => {
    const N = 10;
    const { server, clients } = await createConnections(N);

    try {
      const result = await killSockets({
        src: "127.0.0.1",
        dst: "127.0.0.1",
        mode: "or",
      });
      console.log(`    result: ${JSON.stringify(result)}`);

      assert.ok(
        result.found >= N,
        `expected found >= ${N}, got ${result.found}`,
      );

      if (sockDestroySupported) {
        assert.ok(result.killed >= N, `expected killed >= ${N}, got ${result.killed}`);
        assert.equal(result.destroyErrno, 0);
      }
    } finally {
      cleanup(server, clients);
    }
  });

  it("returns found=0 for non-matching filter", async () => {
    const N = 5;
    const { server, clients } = await createConnections(N);

    try {
      const result = await killSockets({ dst: "198.51.100.1" });
      console.log(`    result: ${JSON.stringify(result)}`);
      assert.equal(result.found, 0);
      assert.equal(result.killed, 0);
    } finally {
      cleanup(server, clients);
    }
  });

  it("sockets are actually destroyed after kill", { skip: !sockDestroySupported }, async () => {
    const N = 10;
    const { server, clients } = await createConnections(N);

    try {
      const result = await killSockets({ dst: "127.0.0.1" });
      console.log(`    result: ${JSON.stringify(result)}`);

      // Wait for destruction to propagate to Node.js layer
      await new Promise((r) => setTimeout(r, 200));

      let destroyed = 0;
      for (const c of clients) {
        if (c.destroyed || c.readyState === "closed") {
          destroyed++;
        }
      }
      assert.ok(
        destroyed >= N,
        `expected at least ${N} destroyed sockets, got ${destroyed}`,
      );
    } finally {
      cleanup(server, clients);
    }
  });
});

describe("killSockets e2e (IPv6)", () => {
  it("finds and kills connections by dst on ::1", async () => {
    const N = 10;
    let fixture;
    try {
      fixture = await createConnections(N, "::1");
    } catch {
      console.log("    skipped: IPv6 loopback not available");
      return;
    }

    try {
      const result = await killSockets({ dst: "::1" });
      console.log(`    result: ${JSON.stringify(result)}`);

      assert.ok(
        result.found >= N,
        `expected found >= ${N}, got ${result.found}`,
      );

      if (sockDestroySupported) {
        assert.ok(result.killed >= N, `expected killed >= ${N}, got ${result.killed}`);
        assert.equal(result.destroyErrno, 0);
      }
    } finally {
      cleanup(fixture.server, fixture.clients);
    }
  });

  it("finds and kills connections by src on ::1", async () => {
    const N = 10;
    let fixture;
    try {
      fixture = await createConnections(N, "::1");
    } catch {
      console.log("    skipped: IPv6 loopback not available");
      return;
    }

    try {
      const result = await killSockets({ src: "::1" });
      console.log(`    result: ${JSON.stringify(result)}`);

      assert.ok(
        result.found >= N,
        `expected found >= ${N}, got ${result.found}`,
      );

      if (sockDestroySupported) {
        assert.ok(result.killed >= N, `expected killed >= ${N}, got ${result.killed}`);
        assert.equal(result.destroyErrno, 0);
      }
    } finally {
      cleanup(fixture.server, fixture.clients);
    }
  });
});

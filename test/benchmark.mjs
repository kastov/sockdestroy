/**
 * Benchmark for sockdestroy — measures kill throughput (RPS).
 * Requires Linux with CAP_NET_ADMIN (run in privileged Docker container).
 * Runner: node test/benchmark.mjs
 *
 * Always exits with code 0 — benchmark results are informational only.
 */

import net from "node:net";
import { performance } from "node:perf_hooks";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { killSockets, hasCapNetAdmin } = require("../lib/index.js");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BATCH_SIZES = [100, 500, 1000, 5000];
const ITERATIONS = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function createConnections(count, host = "127.0.0.1") {
  const server = net.createServer((sock) => sock.resume());
  await new Promise((resolve) => server.listen(0, host, resolve));
  const port = server.address().port;

  const clients = [];
  const batchSize = 200;
  for (let i = 0; i < count; i += batchSize) {
    const batch = Math.min(batchSize, count - i);
    const promises = [];
    for (let j = 0; j < batch; j++) {
      promises.push(
        new Promise((resolve, reject) => {
          const sock = new net.Socket();
          sock.connect(port, host, () => resolve(sock));
          sock.once("error", reject);
        }),
      );
    }
    clients.push(...(await Promise.all(promises)));
  }

  // Let kernel state settle
  await new Promise((r) => setTimeout(r, 50));
  return { server, clients, port };
}

function cleanup(server, clients) {
  for (const c of clients) c.destroy();
  server.close();
}

// ---------------------------------------------------------------------------
// Pre-flight
// ---------------------------------------------------------------------------

if (process.platform !== "linux") {
  console.log("Benchmark requires Linux. Skipping.");
  process.exit(0);
}

if (!hasCapNetAdmin()) {
  console.log("Benchmark requires CAP_NET_ADMIN. Skipping.");
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Probe SOCK_DESTROY support
// ---------------------------------------------------------------------------

{
  const { server, clients } = await createConnections(1);
  const probe = await killSockets({ dst: "127.0.0.1" });
  cleanup(server, clients);
  await new Promise((r) => setTimeout(r, 100));

  if (probe.destroyErrno === 95) {
    console.log(
      "SOCK_DESTROY not supported by this kernel (EOPNOTSUPP).\n" +
        "Benchmark will measure dump+find throughput instead of kill throughput.\n",
    );
  }
}

// ---------------------------------------------------------------------------
// Run benchmarks
// ---------------------------------------------------------------------------

console.log("=== sockdestroy benchmark ===\n");

const allResults = [];

for (const size of BATCH_SIZES) {
  const iterResults = [];

  for (let iter = 0; iter < ITERATIONS; iter++) {
    let fixture;
    try {
      fixture = await createConnections(size);
    } catch (err) {
      console.error(`  Failed to create ${size} connections: ${err.message}`);
      break;
    }

    const t0 = performance.now();
    const result = await killSockets({ dst: "127.0.0.1" });
    const elapsed = performance.now() - t0;

    cleanup(fixture.server, fixture.clients);

    // Use found as metric when SOCK_DESTROY is unavailable
    const effective = result.killed > 0 ? result.killed : result.found;

    iterResults.push({
      killed: result.killed,
      found: result.found,
      timeMs: elapsed,
      opsPerSec: (effective / elapsed) * 1000,
    });

    // Let OS reclaim resources between iterations
    await new Promise((r) => setTimeout(r, 200));
  }

  if (iterResults.length === 0) continue;

  const avg = (arr, key) => arr.reduce((s, r) => s + r[key], 0) / arr.length;
  const min = (arr, key) => Math.min(...arr.map((r) => r[key]));
  const max = (arr, key) => Math.max(...arr.map((r) => r[key]));

  const summary = {
    connections: size,
    avgFound: Math.round(avg(iterResults, "found")),
    avgKilled: Math.round(avg(iterResults, "killed")),
    avgTimeMs: avg(iterResults, "timeMs").toFixed(2),
    avgOpsPerSec: Math.round(avg(iterResults, "opsPerSec")),
    minOpsPerSec: Math.round(min(iterResults, "opsPerSec")),
    maxOpsPerSec: Math.round(max(iterResults, "opsPerSec")),
  };

  allResults.push(summary);
}

// ---------------------------------------------------------------------------
// Output table
// ---------------------------------------------------------------------------

const hasKills = allResults.some((r) => r.avgKilled > 0);
const metric = hasKills ? "Kills" : "Finds";

console.log(
  `Connections | Avg Found | Avg Killed | Avg Time (ms) | Avg ${metric}/sec | Min ${metric}/sec | Max ${metric}/sec`,
);
console.log(
  `----------- | --------- | ---------- | ------------- | ------------- | ------------- | -------------`,
);

for (const r of allResults) {
  console.log(
    `${String(r.connections).padStart(11)} | ` +
      `${String(r.avgFound).padStart(9)} | ` +
      `${String(r.avgKilled).padStart(10)} | ` +
      `${String(r.avgTimeMs).padStart(13)} | ` +
      `${String(r.avgOpsPerSec).padStart(13)} | ` +
      `${String(r.minOpsPerSec).padStart(13)} | ` +
      `${String(r.maxOpsPerSec).padStart(13)}`,
  );
}

console.log("\nDone.");

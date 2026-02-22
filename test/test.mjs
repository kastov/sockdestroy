/**
 * Test suite for sockdestroy
 * Runner: node --test (Node.js built-in, >= 22)
 * Module under test is CJS, imported via createRequire.
 */

import { describe, it, before, mock } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Load a fresh copy of lib/index.js with an optional node-gyp-build stub
 * injected into the module cache, so we control whether `binding` is null
 * or a fake native object.
 *
 * @param {object|null} fakeBinding  – object returned by node-gyp-build, or
 *                                     null to simulate load failure.
 */
function loadModule(fakeBinding) {
  // Evict any previously cached copy of the module under test.
  const indexPath = require.resolve("../lib/index.js");
  const gypBuildPath = require.resolve("node-gyp-build");

  delete require.cache[indexPath];

  // Temporarily replace node-gyp-build in the require cache with a stub.
  const originalGypBuild = require.cache[gypBuildPath];
  require.cache[gypBuildPath] = {
    id: gypBuildPath,
    filename: gypBuildPath,
    loaded: true,
    exports: fakeBinding === null
      ? () => { throw new Error("gyp build failed"); }
      : () => fakeBinding,
  };

  const mod = require("../lib/index.js");

  // Restore original gyp-build entry (or remove the stub).
  if (originalGypBuild) {
    require.cache[gypBuildPath] = originalGypBuild;
  } else {
    delete require.cache[gypBuildPath];
  }

  return mod;
}

// ---------------------------------------------------------------------------
// KillError — class shape and property derivation
// ---------------------------------------------------------------------------

describe("KillError", () => {
  const { KillError } = loadModule(null);

  it("is an instance of Error", () => {
    const err = new KillError("msg", "ERR_UNSUPPORTED_PLATFORM");
    assert.ok(err instanceof Error);
  });

  it("is an instance of KillError", () => {
    const err = new KillError("msg", "ERR_UNSUPPORTED_PLATFORM");
    assert.ok(err instanceof KillError);
  });

  it("sets .name to 'KillError'", () => {
    const err = new KillError("msg", 1);
    assert.equal(err.name, "KillError");
  });

  it("sets .message", () => {
    const err = new KillError("hello world", 0);
    assert.equal(err.message, "hello world");
  });

  describe("when errno is a string", () => {
    it("sets .errno to the string value (backwards compat)", () => {
      const err = new KillError("msg", "ERR_UNSUPPORTED_PLATFORM");
      assert.equal(err.errno, "ERR_UNSUPPORTED_PLATFORM");
    });

    it("sets .code to the same string (Node.js convention)", () => {
      const err = new KillError("msg", "ERR_UNSUPPORTED_PLATFORM");
      assert.equal(err.code, "ERR_UNSUPPORTED_PLATFORM");
    });

    it("sets .code for ERR_BINDING_LOAD", () => {
      const err = new KillError("msg", "ERR_BINDING_LOAD");
      assert.equal(err.code, "ERR_BINDING_LOAD");
    });
  });

  describe("when errno is a number", () => {
    it("sets .errno to the numeric value (backwards compat)", () => {
      const err = new KillError("msg", 1);
      assert.equal(err.errno, 1);
    });

    it("sets .code to null (no string code for raw system errno)", () => {
      const err = new KillError("msg", 1);
      assert.equal(err.code, null);
    });

    it("sets .code to null for errno 0", () => {
      const err = new KillError("msg", 0);
      assert.equal(err.code, null);
    });

    it("sets .code to null for EOPNOTSUPP (95)", () => {
      const err = new KillError("msg", 95);
      assert.equal(err.code, null);
    });
  });

  it("has a stack trace", () => {
    const err = new KillError("msg", 0);
    assert.ok(typeof err.stack === "string" && err.stack.length > 0);
  });
});

// ---------------------------------------------------------------------------
// hasCapNetAdmin — export exists and returns boolean on non-Linux
// ---------------------------------------------------------------------------

describe("hasCapNetAdmin", () => {
  it("is exported as a function", () => {
    const { hasCapNetAdmin } = loadModule(null);
    assert.equal(typeof hasCapNetAdmin, "function");
  });

  it("returns false on non-Linux platform (or when binding absent)", () => {
    const { hasCapNetAdmin } = loadModule(null);
    // On Linux with a missing binding it also returns false.
    // On macOS/Windows it unconditionally returns false.
    const result = hasCapNetAdmin();
    assert.equal(typeof result, "boolean");
    if (process.platform !== "linux") {
      assert.equal(result, false);
    }
  });

  it("delegates to binding.hasCapNetAdmin on Linux when binding is present", () => {
    if (process.platform !== "linux") {
      // Simulate Linux by temporarily patching process.platform.
      // We do this inline to keep the mock isolated.
      const fakeBinding = { hasCapNetAdmin: () => true, killSockets: async () => ({}) };
      const { hasCapNetAdmin } = loadModule(fakeBinding);

      const originalDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
      Object.defineProperty(process, "platform", { value: "linux", configurable: true });
      try {
        assert.equal(hasCapNetAdmin(), true);
      } finally {
        if (originalDescriptor) {
          Object.defineProperty(process, "platform", originalDescriptor);
        }
      }
      return;
    }
    // On actual Linux, just verify it returns a boolean.
    const fakeBinding = { hasCapNetAdmin: () => true, killSockets: async () => ({}) };
    const { hasCapNetAdmin } = loadModule(fakeBinding);
    assert.equal(typeof hasCapNetAdmin(), "boolean");
  });
});

// ---------------------------------------------------------------------------
// killSockets — argument validation (platform-independent)
// ---------------------------------------------------------------------------

describe("killSockets argument validation", () => {
  const { killSockets } = loadModule(null);

  it("throws TypeError when called with no argument", async () => {
    await assert.rejects(() => killSockets(), { name: "TypeError" });
  });

  it("throws TypeError when argument is not an object", async () => {
    await assert.rejects(() => killSockets("bad"), { name: "TypeError" });
  });

  it("throws TypeError when neither src nor dst is provided", async () => {
    await assert.rejects(() => killSockets({}), { name: "TypeError" });
  });

  it("throws TypeError when src is a non-string non-null value", async () => {
    await assert.rejects(() => killSockets({ src: 123 }), { name: "TypeError" });
  });

  it("throws TypeError when dst is a non-string non-null value", async () => {
    await assert.rejects(() => killSockets({ dst: 456 }), { name: "TypeError" });
  });

  it("throws TypeError when mode is invalid", async () => {
    await assert.rejects(
      () => killSockets({ src: "1.2.3.4", mode: "xor" }),
      { name: "TypeError" },
    );
  });

  it("accepts src only", async () => {
    // Will proceed past validation then throw KillError (platform or binding).
    const err = await killSockets({ src: "1.2.3.4" }).catch((e) => e);
    assert.notEqual(err.name, "TypeError");
  });

  it("accepts dst only", async () => {
    const err = await killSockets({ dst: "1.2.3.4" }).catch((e) => e);
    assert.notEqual(err.name, "TypeError");
  });

  it("accepts mode 'or'", async () => {
    const err = await killSockets({ src: "1.2.3.4", mode: "or" }).catch((e) => e);
    assert.notEqual(err.name, "TypeError");
  });

  it("accepts mode 'and'", async () => {
    const err = await killSockets({ src: "1.2.3.4", mode: "and" }).catch((e) => e);
    assert.notEqual(err.name, "TypeError");
  });

  it("accepts null src (treated as absent)", async () => {
    // src is null → coerces to absent; dst must be provided to pass src+dst check.
    const err = await killSockets({ src: null, dst: "1.2.3.4" }).catch((e) => e);
    assert.notEqual(err.name, "TypeError");
  });
});

// ---------------------------------------------------------------------------
// killSockets — KillError on non-Linux or missing binding
// ---------------------------------------------------------------------------

describe("killSockets KillError propagation", () => {
  it("throws KillError with code ERR_UNSUPPORTED_PLATFORM on non-Linux", async () => {
    if (process.platform === "linux") {
      // Cannot test this path on Linux without patching process.platform.
      const { killSockets, KillError } = loadModule({
        hasCapNetAdmin: () => true,
        killSockets: async () => ({}),
      });
      const originalDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
      Object.defineProperty(process, "platform", { value: "darwin", configurable: true });
      try {
        const err = await killSockets({ src: "1.2.3.4" }).catch((e) => e);
        assert.ok(err instanceof KillError);
        assert.equal(err.code, "ERR_UNSUPPORTED_PLATFORM");
        assert.equal(err.errno, "ERR_UNSUPPORTED_PLATFORM");
      } finally {
        if (originalDescriptor) {
          Object.defineProperty(process, "platform", originalDescriptor);
        }
      }
      return;
    }
    // On non-Linux the module itself exposes the right error.
    const { killSockets, KillError } = loadModule(null);
    const err = await killSockets({ src: "1.2.3.4" }).catch((e) => e);
    assert.ok(err instanceof KillError);
    assert.equal(err.code, "ERR_UNSUPPORTED_PLATFORM");
    assert.equal(err.errno, "ERR_UNSUPPORTED_PLATFORM");
  });

  it("throws KillError with code ERR_BINDING_LOAD when binding is absent on Linux", async () => {
    if (process.platform !== "linux") {
      // Patch platform to linux so we reach the binding check.
      const { killSockets, KillError } = loadModule(null);
      const originalDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
      Object.defineProperty(process, "platform", { value: "linux", configurable: true });
      try {
        const err = await killSockets({ src: "1.2.3.4" }).catch((e) => e);
        assert.ok(err instanceof KillError);
        assert.equal(err.code, "ERR_BINDING_LOAD");
        assert.equal(err.errno, "ERR_BINDING_LOAD");
      } finally {
        if (originalDescriptor) {
          Object.defineProperty(process, "platform", originalDescriptor);
        }
      }
      return;
    }
    // On actual Linux with no prebuild, binding may already be null.
    const { killSockets, KillError } = loadModule(null);
    const err = await killSockets({ src: "1.2.3.4" }).catch((e) => e);
    assert.ok(err instanceof KillError);
    assert.equal(err.code, "ERR_BINDING_LOAD");
  });

  it("re-throws native errors as KillError with null code", async () => {
    const nativeError = Object.assign(new Error("Operation not permitted"), { errno: 1 });
    const fakeBinding = {
      hasCapNetAdmin: () => true,
      killSockets: async () => { throw nativeError; },
    };
    const { killSockets, KillError } = loadModule(fakeBinding);

    const originalDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    try {
      const err = await killSockets({ src: "1.2.3.4" }).catch((e) => e);
      assert.ok(err instanceof KillError);
      assert.equal(err.errno, 1);
      assert.equal(err.code, null);
      assert.equal(err.message, "Operation not permitted");
    } finally {
      if (originalDescriptor) {
        Object.defineProperty(process, "platform", originalDescriptor);
      }
    }
  });

  it("uses errno 0 when native error has no errno", async () => {
    const nativeError = new Error("unknown native error");
    const fakeBinding = {
      hasCapNetAdmin: () => true,
      killSockets: async () => { throw nativeError; },
    };
    const { killSockets, KillError } = loadModule(fakeBinding);

    const originalDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    try {
      const err = await killSockets({ src: "1.2.3.4" }).catch((e) => e);
      assert.ok(err instanceof KillError);
      assert.equal(err.errno, 0);
      assert.equal(err.code, null);
    } finally {
      if (originalDescriptor) {
        Object.defineProperty(process, "platform", originalDescriptor);
      }
    }
  });

  it("resolves with KillResult shape when binding succeeds", async () => {
    const killResult = { killed: 2, found: 3, destroyErrno: 0 };
    const fakeBinding = {
      hasCapNetAdmin: () => true,
      killSockets: async () => killResult,
    };
    const { killSockets } = loadModule(fakeBinding);

    const originalDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    try {
      const result = await killSockets({ src: "1.2.3.4" });
      assert.equal(result.killed, 2);
      assert.equal(result.found, 3);
      assert.equal(result.destroyErrno, 0);
    } finally {
      if (originalDescriptor) {
        Object.defineProperty(process, "platform", originalDescriptor);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Module exports shape
// ---------------------------------------------------------------------------

describe("module exports", () => {
  const mod = loadModule(null);

  it("exports KillError", () => {
    assert.equal(typeof mod.KillError, "function");
  });

  it("exports killSockets", () => {
    assert.equal(typeof mod.killSockets, "function");
  });

  it("exports hasCapNetAdmin", () => {
    assert.equal(typeof mod.hasCapNetAdmin, "function");
  });

  it("does not export unexpected properties", () => {
    const keys = Object.keys(mod).sort();
    assert.deepEqual(keys, ["KillError", "hasCapNetAdmin", "killSockets"].sort());
  });
});

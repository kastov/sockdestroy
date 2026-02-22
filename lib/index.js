"use strict";

const path = require("node:path");

class KillError extends Error {
  constructor(message, errno) {
    super(message);
    this.name = "KillError";
    this.errno = errno;
    this.code = typeof errno === "string" ? errno : null;
  }
}

let binding;
try {
  binding = require("node-gyp-build")(path.join(__dirname, ".."));
} catch (e) {
  binding = null;
}

/**
 * @param {{ src?: string, dst?: string, mode?: 'or' | 'and' }} filter
 * @returns {Promise<{ killed: number, found: number, destroyErrno: number }>}
 */
async function killSockets(filter) {
  if (!filter || typeof filter !== "object") {
    throw new TypeError('Argument must be an object { src?: string, dst?: string, mode?: "or" | "and" }');
  }

  if (!filter.src && !filter.dst) {
    throw new TypeError("At least one of src or dst must be provided");
  }

  if (filter.src !== undefined && filter.src !== null && typeof filter.src !== "string") {
    throw new TypeError("src must be a string");
  }

  if (filter.dst !== undefined && filter.dst !== null && typeof filter.dst !== "string") {
    throw new TypeError("dst must be a string");
  }

  if (filter.mode !== undefined && filter.mode !== "or" && filter.mode !== "and") {
    throw new TypeError('mode must be "or" or "and"');
  }

  if (process.platform !== "linux") {
    throw new KillError("sockdestroy only works on Linux", "ERR_UNSUPPORTED_PLATFORM");
  }

  if (!binding) {
    throw new KillError("sockdestroy: Native binding failed to load", "ERR_BINDING_LOAD");
  }

  try {
    return await binding.killSockets(filter);
  } catch (err) {
    throw new KillError(err.message, err.errno !== undefined ? err.errno : 0);
  }
}

/**
 * Check if the current process has CAP_NET_ADMIN capability.
 * @returns {boolean}
 */
function hasCapNetAdmin() {
  if (process.platform !== "linux") {
    return false;
  }
  if (!binding) {
    return false;
  }
  return binding.hasCapNetAdmin();
}

module.exports = { killSockets, hasCapNetAdmin, KillError };

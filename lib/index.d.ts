export class KillError extends Error {
  /** Error name, always 'KillError' */
  name: 'KillError';
  /** System errno code, or 0 if not applicable */
  errno: number | string;
  /** String error code (Node.js convention). Set when errno is a string identifier, null otherwise. */
  code: string | null;
  constructor(message: string, errno: number | string);
}

export interface KillResult {
  /** Number of TCP sockets successfully destroyed */
  killed: number;
  /** Number of TCP sockets found matching the filter (before destroy attempt) */
  found: number;
  /** First errno from SOCK_DESTROY attempt, 0 if all succeeded or none attempted. E.g. EPERM=1, EOPNOTSUPP=95. */
  destroyErrno: number;
}

export interface KillFilter {
  /** Source IP address to filter (IPv4 or IPv6). Optional. */
  src?: string;
  /** Destination IP address to filter (IPv4 or IPv6). Optional. */
  dst?: string;
  /**
   * Filter mode when both src and dst are provided.
   * - 'or' (default): Kill sockets matching src OR dst (union)
   * - 'and': Kill sockets matching src AND dst (intersection)
   */
  mode?: 'or' | 'and';
}

/**
 * Kill TCP sockets matching the given filter criteria via Linux netlink SOCK_DESTROY.
 *
 * Equivalent to `ss -K src <IP>` and/or `ss -K dst <IP>`.
 *
 * At least one of `src` or `dst` must be provided.
 * Requires CAP_NET_ADMIN capability (or root).
 * Linux only (kernel >= 4.5 with CONFIG_INET_DIAG_DESTROY=y).
 * Scans active TCP connection states (not LISTEN/CLOSE/TIME_WAIT).
 *
 * @param filter - Object with src and/or dst IP addresses and optional mode
 * @returns Promise resolving to KillResult with killed/found counts and first destroy errno
 * @throws {TypeError} If arguments are invalid
 * @throws {KillError} If operation fails (permission denied, invalid IP, etc.)
 *
 * @example
 * // Kill all connections from source IP
 * const { killed } = await killSockets({ src: '10.0.0.1' });
 *
 * @example
 * // Kill connections matching src OR dst (default, union)
 * const result = await killSockets({ src: '10.0.0.1', dst: '192.168.1.100' });
 *
 * @example
 * // Kill connections matching src AND dst (intersection)
 * const result = await killSockets({ src: '10.0.0.1', dst: '192.168.1.100', mode: 'and' });
 *
 * @example
 * // IPv6 support
 * const result = await killSockets({ src: '::1' });
 */
export function killSockets(filter: KillFilter): Promise<KillResult>;

/**
 * Check if the current process has CAP_NET_ADMIN capability.
 *
 * Uses the capget() syscall directly (no libcap dependency).
 * Returns false on non-Linux platforms or if the native binding failed to load.
 *
 * @returns true if CAP_NET_ADMIN is in the effective capability set
 *
 * @example
 * if (!hasCapNetAdmin()) {
 *   console.error('CAP_NET_ADMIN required. Run with: --cap-add=NET_ADMIN');
 *   process.exit(1);
 * }
 */
export function hasCapNetAdmin(): boolean;

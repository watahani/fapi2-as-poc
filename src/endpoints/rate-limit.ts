/**
 * Minimal in-memory fixed-window rate limiter (NFR-6; RFC 9126 §2.3 requires
 * a 429 path for the PAR endpoint, RFC 7009 §5 the same defences for
 * revocation). Per-instance only — production-grade limiting is a P4
 * concern; this bounds abuse of the unauthenticated-facing endpoints.
 */
export class FixedWindowRateLimiter {
  private windows = new Map<string, { start: number; count: number }>();
  private lastSweepMs = 0;

  constructor(
    private readonly limit: number,
    private readonly windowMs = 60_000,
    /** Hard cap on tracked keys; beyond it new keys fail closed (429) so a
     * rotating-source flood cannot grow the map or turn sweeps quadratic. */
    private readonly maxKeys = 50_000,
  ) {}

  /** true = allowed; false = over the limit for this window. */
  allow(key: string, now = Date.now()): boolean {
    if (this.limit <= 0) return true; // disabled
    const w = this.windows.get(key);
    if (w && now - w.start < this.windowMs) {
      w.count += 1;
      return w.count <= this.limit;
    }
    // New or rolled-over window. Sweep expired entries at most once per
    // window (O(n) amortised, not per request).
    if (this.windows.size >= this.maxKeys && now - this.lastSweepMs >= this.windowMs) {
      this.lastSweepMs = now;
      for (const [k, v] of this.windows) {
        if (now - v.start >= this.windowMs) this.windows.delete(k);
      }
    }
    // Still at the cap after sweeping (all windows live) → fail closed.
    if (!w && this.windows.size >= this.maxKeys) return false;
    this.windows.set(key, { start: now, count: 1 });
    return true;
  }
}

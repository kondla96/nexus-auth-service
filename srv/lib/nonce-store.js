"use strict";

/**
 * In-memory nonce store with TTL.
 *
 * Maps nonce → { user, createdAt, status, hash }
 *
 * Lifecycle:
 *   1. license-service.js calls create(userId) → returns a nonce string.
 *   2. Nexus POSTs to /nexus/callback?n=<nonce> with the hash.
 *      callback-service.js calls complete(nonce, hash) → marks it done.
 *   3. Fiori client polls GET /api/license/result(nonce='...').
 *      license-service.js calls get(nonce) and returns status/hash.
 *   4. After TTL_MS the entry expires and is auto-deleted.
 *
 * IMPORTANT: This is intentionally in-memory.
 *   - Safe for a SINGLE CF instance only.
 *   - mta.yaml must set instances: 1.
 *   - If you need to scale, replace this module with a Redis-backed
 *     implementation — the interface (create / complete / get) is unchanged.
 */

const crypto = require("crypto");

const TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * @type {Map<string, {
 *   user:      string,
 *   createdAt: number,
 *   status:    'pending' | 'complete',
 *   hash:      string
 * }>}
 */
const store = new Map();

/**
 * Create a new nonce for userId. Returns the nonce string.
 * @param {string} user
 * @returns {string}
 */
function create(user) {
  const nonce = crypto.randomBytes(24).toString("base64url");
  store.set(nonce, { user, createdAt: Date.now(), status: "pending", hash: "" });
  return nonce;
}

/**
 * Mark a nonce as complete with the received hash.
 * Returns true on success, false if nonce not found or expired.
 * @param {string} nonce
 * @param {string} hash
 * @returns {boolean}
 */
function complete(nonce, hash) {
  const entry = store.get(nonce);
  if (!entry || Date.now() - entry.createdAt > TTL_MS) {
    store.delete(nonce);
    return false;
  }
  entry.hash = hash;
  entry.status = "complete";
  return true;
}

/**
 * Retrieve a nonce entry, or null if not found / expired.
 * @param {string} nonce
 * @returns {{ user: string, status: string, hash: string } | null}
 */
function get(nonce) {
  const entry = store.get(nonce);
  if (!entry) return null;
  if (Date.now() - entry.createdAt > TTL_MS) {
    store.delete(nonce);
    return null;
  }
  return entry;
}

// Periodic cleanup: remove entries older than TTL_MS.
// .unref() lets the process exit cleanly even if this interval is pending.
setInterval(() => {
  const cutoff = Date.now() - TTL_MS;
  for (const [k, v] of store) {
    if (v.createdAt < cutoff) store.delete(k);
  }
}, 60_000).unref();

module.exports = { create, complete, get };

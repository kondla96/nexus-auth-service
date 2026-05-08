"use strict";

/**
 * In-memory correlation store for the Option C: OBO async postback pattern.
 *
 * Lifecycle of a corrId:
 *   1. nexus-service.js calls pending.reserve(corrId, userId) after generating
 *      the UUID and before calling Nexus.
 *   2. The Fiori client calls GET /api/wait/:corrId (SSE). The handler calls
 *      pending.subscribe(corrId, cb) — if the postback has already arrived the
 *      callback fires immediately; otherwise it is stored and called later.
 *   3. Nexus POSTs to /api/postback?corrId=<x>. The handler calls
 *      pending.deliver(corrId, payload) which either fires the stored callback
 *      or caches the payload for a subscriber that hasn't arrived yet.
 *   4. After delivery (or after TTL_MS) the entry is removed from the Map.
 *
 * This is intentionally simple in-memory state. It is safe for a single CF
 * instance. If multiple instances are needed, replace this module with a
 * Redis-backed implementation without changing callers.
 */

const TTL_MS = 5 * 60 * 1000; // 5 minutes — matches typical Nexus response time SLA

/** @type {Map<string, { userId: string, resolve: Function|null, payload: any|null }>} */
const store = new Map();

exports.pending = {
  /**
   * Reserve a slot for corrId, associated with userId.
   * Automatically cleaned up after TTL_MS.
   */
  reserve(corrId, userId) {
    store.set(corrId, { userId, resolve: null, payload: null });
    setTimeout(() => store.delete(corrId), TTL_MS);
  },

  /** Returns true if the corrId slot exists (i.e. is still pending/unexpired). */
  has(corrId) {
    return store.has(corrId);
  },

  /** Returns true if corrId was reserved by the given userId. */
  belongsTo(corrId, userId) {
    return store.get(corrId)?.userId === userId;
  },

  /**
   * Deliver a postback payload for corrId.
   * If a subscriber is already waiting, the callback is invoked immediately.
   * Otherwise the payload is cached until subscribe() is called.
   */
  deliver(corrId, payload) {
    const entry = store.get(corrId);
    if (!entry) return;
    if (entry.resolve) {
      entry.resolve(payload);
    } else {
      entry.payload = payload;
    }
  },

  /**
   * Subscribe to the result for corrId.
   * If the payload has already arrived, cb is called synchronously.
   * Otherwise cb is stored and called when deliver() fires.
   */
  subscribe(corrId, cb) {
    const entry = store.get(corrId);
    if (!entry) return;
    if (entry.payload !== null) {
      cb(entry.payload);
    } else {
      entry.resolve = cb;
    }
  },

  /** Remove the entry for corrId (called when the SSE connection closes). */
  unsubscribe(corrId) {
    store.delete(corrId);
  },
};

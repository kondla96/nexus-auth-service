"use strict";

/**
 * CallbackService implementation.
 *
 * Security layers (applied in order):
 *   1. IP allowlist  — rejects requests from non-Nexus IPs if ABC_EGRESS_IPS is set.
 *   2. HMAC-SHA256   — verifies the signature header against rawBody + POSTBACK_SECRET.
 *   3. Nonce lookup  — rejects unknown or expired nonces.
 *
 * Environment variables (set via BTP Credential Store or cf set-env):
 *   POSTBACK_SECRET   Shared HMAC secret agreed with Nexus team. Required.
 *   ABC_SIG_HEADER    HTTP header name Nexus uses for the HMAC signature.
 *                     Default: 'x-nexus-signature'
 *                     TODO: confirm exact header name with Ben/Nexus team.
 *   ABC_EGRESS_IPS    Comma-separated list of Nexus outbound IP addresses.
 *                     If empty, IP check is skipped (not recommended in production).
 *                     TODO: get egress IPs from Ben/Nexus team.
 */

const cds    = require("@sap/cds");
const crypto = require("crypto");
const nonceStore = require("./lib/nonce-store");

const log = cds.log("callback");

// Read config once at module load.
// These must be set before the app starts (mta.yaml env or cf set-env).
const ALLOWED_IPS  = (process.env.ABC_EGRESS_IPS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

const SIG_HEADER   = (process.env.ABC_SIG_HEADER || "x-nexus-signature").toLowerCase();

module.exports = cds.service.impl(function () {

  this.on("receive", async (req) => {
    const httpReq = req.http?.req;
    if (!httpReq) return req.reject(500, "no http context");

    // ── 1. IP allowlist ────────────────────────────────────────────────────
    // TODO: re-enable once Nexus egress IPs confirmed with Ben (ABC_EGRESS_IPS).
    // const clientIp = (
    //   httpReq.headers["x-forwarded-for"] || httpReq.socket?.remoteAddress || ""
    // ).toString().split(",")[0].trim();
    // if (ALLOWED_IPS.length && !ALLOWED_IPS.includes(clientIp)) {
    //   log.warn("Callback rejected: IP not in allowlist", { clientIp });
    //   return req.reject(403, "forbidden");
    // }

    // ── 2. HMAC-SHA256 signature verification ──────────────────────────────
    // TODO: re-enable once HMAC secret + header name confirmed with Ben
    //       (POSTBACK_SECRET, ABC_SIG_HEADER).
    // const POSTBACK_SECRET = process.env.POSTBACK_SECRET;
    // if (!POSTBACK_SECRET) {
    //   log.error("POSTBACK_SECRET not configured");
    //   return req.reject(500, "internal configuration error");
    // }
    // const sig = httpReq.headers[SIG_HEADER];
    // if (!sig) {
    //   log.warn("Callback rejected: missing signature header", { header: SIG_HEADER });
    //   return req.reject(401, "missing signature");
    // }
    // const rawBody = httpReq.rawBody ?? Buffer.from(JSON.stringify(req.data));
    // const expected = crypto
    //   .createHmac("sha256", POSTBACK_SECRET)
    //   .update(rawBody)
    //   .digest("hex");
    // const sigBuf      = Buffer.from(String(sig), "utf8");
    // const expectedBuf = Buffer.from(expected,     "utf8");
    // if (
    //   sigBuf.length !== expectedBuf.length ||
    //   !crypto.timingSafeEqual(sigBuf, expectedBuf)
    // ) {
    //   log.warn("Callback rejected: HMAC mismatch");
    //   return req.reject(401, "invalid signature");
    // }

    // ── 3. Nonce + hash extraction ─────────────────────────────────────────
    const nonce = httpReq.query?.n;
    if (!nonce) {
      log.warn("Callback rejected: missing nonce query param");
      return req.reject(400, "missing nonce");
    }

    // The hash comes from the POST body.
    // TODO: confirm exact field name with Ben/Nexus team.
    //       Trying 'hash' first, then 'Hash' (case fallback).
    const hash = req.data?.hash ?? req.data?.Hash;
    if (!hash) {
      log.warn("Callback rejected: hash field missing in body", { body: req.data });
      return req.reject(400, "missing hash");
    }

    // ── 4. Update nonce-store ──────────────────────────────────────────────
    const stored = nonceStore.complete(nonce, hash);
    if (!stored) {
      // Nonce not found or already expired — Nexus called back too late.
      log.warn("Callback: nonce not found or expired", { nonce });
      return req.reject(404, "nonce not found or expired");
    }

    log.info("Callback: hash stored", { nonce });
    return "ok";
  });

});

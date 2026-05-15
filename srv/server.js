"use strict";

/**
 * Custom Express bootstrap hooks for the CAP server.
 *
 * Registers two things before CDS takes over:
 *
 *   1. Raw body capture middleware for POST /nexus/callback
 *      The HMAC-SHA256 signature in callback-service.js must be computed
 *      against the EXACT bytes Nexus sent. Express/CAP body parsers consume
 *      the stream and JSON-parse the body — after that the original bytes are
 *      gone. We capture them here, before any parsing, and attach them as
 *      req.rawBody so callback-service.js can use them.
 *
 *   2. GET /nexus/health — public liveness probe (no auth required).
 *      Used by BTP health checks and monitoring.
 */

const cds = require("@sap/cds");

cds.on("bootstrap", (app) => {

  const nonceStore = require("./lib/nonce-store");
  const log        = cds.log("callback");

  // ── JWT payload decoder (no-verify — only used for user identity lookup) ──
  function decodeJwtPayload(jwt) {
    try {
      const parts = (jwt || "").split(".");
      if (parts.length < 2) return null;
      return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    } catch (_) { return null; }
  }

  // ── GET /nexus/callback and /nexus/callback/:nonce — probe responses ───────
  // Nexus sends a GET to validate the postBack URL is reachable.
  app.get("/nexus/callback",        (_req, res) => res.status(200).end());
  app.get("/nexus/callback/:nonce", (_req, res) => res.status(200).end());

  // ── POST /nexus/callback — Nexus token delivery ───────────────────────────
  // Nexus ALWAYS calls back to /nexus/callback — it strips everything after
  // the base path (query strings AND path segments) from the postBack URL.
  //
  // Correlation strategy: the callback body includes a `jwt` field which is
  // the Graph token (Token B) we passed to Nexus during requestHash. We decode
  // the JWT payload (no signature verification needed) to extract the user's
  // UPN, then match it to the oldest pending nonce for that user.
  function handleCallbackPost(req, res) {
    const chunks = [];
    req.on("data",  chunk => chunks.push(chunk));
    req.on("error", err   => {
      log.error("Callback stream error", { message: err.message });
      res.status(500).json({ error: "stream error" });
    });
    req.on("end", () => {
      const rawBody = Buffer.concat(chunks).toString("utf8");

      // Parse body — Nexus sends JSON: { token, userId, restEndPoint, jwt }
      let parsed = {};
      try { parsed = JSON.parse(rawBody); } catch (_) { /* not JSON — probe or malformed */ }

      const token = parsed.token ?? parsed.hash ?? parsed.Hash ?? parsed.hashValue;
      if (!token) {
        // No token → probe POST. Log body and acknowledge.
        log.info("Callback received (probe / no token) — body: " + (rawBody || "(empty)"));
        return res.status(200).json({ status: "ok" });
      }

      // Decode the jwt to find which user this callback belongs to.
      const jwtPayload = decodeJwtPayload(parsed.jwt);
      const user = jwtPayload?.upn || jwtPayload?.unique_name || jwtPayload?.preferred_username || jwtPayload?.email;

      if (!user) {
        log.warn("Callback: token received but could not identify user from jwt", { token });
        return res.status(400).json({ error: "cannot identify user" });
      }

      const matchedNonce = nonceStore.completeByUser(user, parsed);
      if (!matchedNonce) {
        log.warn("Callback: no pending nonce found for user", { user });
        return res.status(404).json({ error: "no pending session for user" });
      }

      log.info("Callback: token stored successfully", { user, nonce: matchedNonce });
      res.json({ status: "ok" });
    });
  }

  app.post("/nexus/callback",        handleCallbackPost);
  app.post("/nexus/callback/:nonce", handleCallbackPost);

  // ── GET /nexus/health — public liveness check ─────────────────────────────
  app.get("/nexus/health", (_req, res) => {
    res.json({
      status:  "UP",
      app:     "nexus-bridge",
      version: process.env.npm_package_version || "1.0.0",
      time:    new Date().toISOString(),
    });
  });

});

module.exports = cds.server;


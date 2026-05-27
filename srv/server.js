"use strict";

/**
 * Custom Express bootstrap for the CAP server.
 *
 * Registers public routes before CDS takes over:
 *
 *   1. POST /nexus/callback — receives the Nexus license token delivery.
 *      Registered here (before CDS) so it is fully public; no XSUAA auth required.
 *      Correlates the callback to the waiting user via the JWT in the POST body.
 *
 *   2. GET /nexus/callback — probe response (Nexus validates the URL is reachable).
 *
 *   3. GET /nexus/health — public liveness probe (no auth required).
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
  // Nexus POSTs { token, userId, restEndPoint, jwt } to this endpoint.
  // Correlation: we decode the jwt field (no signature verify — already
  // validated by Nexus) to extract the user email, then match it to the
  // oldest pending nonce for that user in the nonce-store.
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
        log.warn("Callback: token received but no pending nonce for user (expired or direct call)", { user });
        return res.status(200).json({ status: "ok" });
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


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

  // ── Raw body capture for /nexus/callback ──────────────────────────────────
  // Must be registered BEFORE any body-parser middleware.
  // Callback-service.js reads req.rawBody for HMAC verification.
  app.use("/nexus/callback", (req, _res, next) => {
    const chunks = [];
    req.on("data", chunk => chunks.push(chunk));
    req.on("end",  ()    => { req.rawBody = Buffer.concat(chunks); next(); });
    req.on("error", next);
  });

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


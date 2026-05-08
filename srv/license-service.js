"use strict";

/**
 * LicenseService implementation.
 *
 * requestHash():
 *   - Generates a nonce and stores it in the in-memory nonce-store (5-min TTL).
 *   - Calls Nexus via the AbcLicenseServer BTP destination. The destination is
 *     configured as OAuth2SAMLBearerAssertion — BTP Destination service builds
 *     a SAML assertion for the logged-in user, exchanges it with Entra for a
 *     delegated Microsoft Graph token, and injects it as Authorization: Bearer.
 *     Static query params (id, app, type, env) are embedded in the destination
 *     URL.queries.* properties. Only the dynamic postback URL is added here.
 *   - Returns { nonce } immediately. The Fiori client polls result(nonce).
 *
 * result(nonce):
 *   - Returns { status, hash } from the nonce-store.
 *   - status: 'pending' | 'complete' | 'expired'
 *   - The nonce is marked complete when Nexus POSTs to POST /nexus/callback?n=<nonce>.
 */

const cds = require("@sap/cds");
const { executeHttpRequest } = require("@sap-cloud-sdk/http-client");
const nonceStore = require("./lib/nonce-store");

const log = cds.log("license");

module.exports = cds.service.impl(function () {

  // ── requestHash ─────────────────────────────────────────────────────────────
  this.on("requestHash", async (req) => {
    const userId = req.user.id;

    // 1. Create nonce tied to this user (5-min TTL, auto-expires).
    const nonce = nonceStore.create(userId);

    // 2. Build the postback URL Nexus will POST the hash result to.
    //    POSTBACK_BASE = ${default-url} from mta.yaml (CF app route, no trailing slash).
    const base = (process.env.POSTBACK_BASE || "").replace(/\/$/, "");
    const postbackUrl = `${base}/nexus/callback?n=${encodeURIComponent(nonce)}`;

    // 3. Resolve the user's XSUAA JWT from the Authorization header.
    //    The Cloud SDK needs this to perform the OAuth2SAMLBearerAssertion
    //    token exchange with Entra on behalf of the logged-in user.
    const authHeader = req.http?.req?.headers?.authorization || "";
    const userJwt = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
    log.info("JWT extracted", { hasJwt: !!userJwt, userId });

    // 4. Call Nexus via NexusLicenseServer destination (OAuth2SAMLBearerAssertion).
    //    The destination carries the static query params (id, app, type, env)
    //    via URL.queries.* additional properties. We only add the dynamic postback.
    //    Nexus responds 200/202 immediately; the actual hash arrives via callback.
    try {
      const resp = await executeHttpRequest(
        { destinationName: "NexusLicenseServer", jwt: userJwt },
        {
          method: "POST",
          url: "/requestHash",
          params: { postBack: postbackUrl },
        },
        { fetchCsrfToken: false }
      );

      if (resp.status >= 400) {
        log.error("Nexus rejected request", { status: resp.status, data: resp.data, userId });
        return req.error(502, "Nexus rejected the request");
      }
    } catch (err) {
      log.error("requestHash call failed", err.message, { userId, cause: err.cause?.message || err.stack?.split("\n")[1] });
      return req.error(500, "internal error calling Nexus");
    }

    log.info("requestHash dispatched", { userId, nonce });
    return { nonce };
  });

  // ── result ──────────────────────────────────────────────────────────────────
  this.on("result", async (req) => {
    const { nonce } = req.data;
    const entry = nonceStore.get(nonce);

    if (!entry) return { status: "expired", hash: "" };

    // Prevent one user from polling another user's nonce.
    if (entry.user !== req.user.id) return req.reject(403, "wrong user");

    if (entry.status === "complete") return { status: "complete", hash: entry.hash };
    return { status: "pending", hash: "" };
  });

});

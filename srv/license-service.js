"use strict";

const cds        = require("@sap/cds");
const nonceStore = require("./lib/nonce-store");

const log = cds.log("license");

module.exports = cds.service.impl(async function () {

  // Connect to Nexus via the BTP Destination "nexusPrincipalProp".
  // Authentication type OAuth2SAMLBearerAssertion on that destination means BTP
  // automatically builds a SAML assertion from the logged-in user's XSUAA token,
  // exchanges it with Azure AD, and injects the resulting delegated Entra Bearer
  // token into every outbound request — no MSAL, no manual token exchange needed.
  const nexusService = await cds.connect.to("ThirdPartyAppService");

  // requestHash — creates a nonce, calls Nexus /requestHash (user identity
  // propagated automatically by the destination), returns the nonce immediately.
  // Nexus POSTs the hash asynchronously to POST /nexus/callback/:nonce.
  this.on("requestHash", async (req) => {
    const userId = req.user.id;

    // 1. Create nonce (5-min TTL).
    const nonce = nonceStore.create(userId);

    // 2. Build postback URL.
    //    Nonce is in the URL PATH (not query string) because Nexus strips
    //    query params before making the callback POST.
    const base = (process.env.POSTBACK_BASE || "").replace(/\/$/, "");
    const postbackUrl = base + "/nexus/callback/" + encodeURIComponent(nonce);

    // 3. Call Nexus via BTP Destination (token exchange is automatic).
    //    Destination URL.queries.* additional properties (id, app, type, env)
    //    are appended by BTP to every request — only postBack is dynamic.
    let nexusStatus = "ok";
    try {
      await nexusService.tx(req).send(
        "POST",
        "/requestHash?postBack=" + encodeURIComponent(postbackUrl),
        ""
      );
      log.info("requestHash dispatched to Nexus", { userId, nonce });
    } catch (err) {
      nexusStatus = err.rootCause?.message || err.message;
      log.error("Nexus requestHash call failed (nonce still active)", {
        userId, nonce, message: err.message,
      });
    }

    return { nonce, nexusStatus };
  });

  // result — polls nonce-store for Nexus token data.
  this.on("result", async (req) => {
    const { nonce } = req.data;
    const entry = nonceStore.get(nonce);
    if (!entry) return { status: "expired", token: "", userId: null, restEndPoint: "", jwt: "" };
    if (entry.user !== req.user.id) return req.reject(403, "wrong user");
    if (entry.status === "complete") return {
      status:       "complete",
      token:        entry.token,
      userId:       entry.userId,
      restEndPoint: entry.restEndPoint,
      jwt:          entry.jwt,
    };
    return { status: "pending", token: "", userId: null, restEndPoint: "", jwt: "" };
  });

});

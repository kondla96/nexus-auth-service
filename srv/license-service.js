"use strict";

const cds                  = require("@sap/cds");
const { executeHttpRequest } = require("@sap-cloud-sdk/http-client");
const { getDestination }   = require("@sap-cloud-sdk/connectivity");
const nonceStore           = require("./lib/nonce-store");

const log = cds.log("license");

module.exports = cds.service.impl(async function () {

  // requestHash — creates a nonce, calls Nexus /requestHash, returns the nonce
  // immediately. Nexus POSTs the hash asynchronously to POST /nexus/callback.
  this.on("requestHash", async (req) => {
    const userId = req.user.id;

    // 1. Create nonce (5-min TTL).
    const nonce = nonceStore.create(userId);

    // 2. Build postback URL.
    //    Nonce is in the URL PATH (not query string) because Nexus strips
    //    query params before making the callback POST.
    const base = (process.env.POSTBACK_BASE || "").replace(/\/$/, "");
    const postbackUrl = base + "/nexus/callback/" + encodeURIComponent(nonce);

    // 3. Call Nexus via BTP Destination "nexusPrincipalProp" (NoAuthentication).
    //    executeHttpRequest is used instead of cds remote-service send() because
    //    it reliably forwards custom headers. The XSUAA Bearer token is passed
    //    so Nexus can validate the user identity directly.
    //    Destination URL.queries.* (id, app, type, env) are appended automatically.
    const authHeader = req.http.req.headers["authorization"];

    let nexusStatus = "ok";
    try {
      const dest = await getDestination({ destinationName: "nexusPrincipalProp" });
      await executeHttpRequest(dest, {
        method:  "POST",
        url:     "/requestHash",
        params:  { postBack: postbackUrl },
        headers: { Authorization: authHeader },
        data:    "",
      });
      log.info("requestHash dispatched to Nexus", { userId, nonce });
    } catch (err) {
      const nexusBody = err.response?.data ?? err.cause?.response?.data ?? null;
      nexusStatus = err.message;
      log.error("Nexus requestHash call failed (nonce still active)", {
        userId, nonce,
        httpStatus:   err.response?.status ?? err.cause?.response?.status,
        nexusBody,
        message:      err.message,
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

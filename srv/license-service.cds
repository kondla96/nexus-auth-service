/**
 * LicenseService — exposed at /api/license
 *
 * Requires an authenticated user (XSUAA JWT validated by @sap/xssec via CAP).
 *
 * Flow:
 *   1. requestHash() — client calls this; service generates a nonce, calls
 *      Nexus via the AbcLicenseServer BTP destination (which performs the
 *      OAuth2SAMLBearerAssertion exchange and injects a Graph token), then
 *      returns the nonce immediately.
 *
 *   2. result(nonce) — client polls this every ~1.5 s until status='complete'.
 *      When Nexus POSTs the hash to POST /nexus/callback?n=<nonce>, the
 *      nonce-store is updated and the next poll returns the hash.
 *
 * No token-exchange code here — all handled by BTP Destination service.
 */
@path: '/api/license'
@requires: 'authenticated-user'
service LicenseService {

  /**
   * Initiates a Nexus license-hash request.
   * Returns a nonce immediately. Poll result(nonce) for the hash.
   */
  action requestHash() returns { nonce : String };

  /**
   * Poll for the result of a previous requestHash call.
   * status: 'pending' | 'complete' | 'expired'
   * hash is populated only when status = 'complete'.
   */
  function result(nonce : String) returns {
    status : String;
    hash   : String;
  };
}

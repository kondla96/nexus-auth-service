/**
 * CallbackService — POST /nexus/callback
 *
 * Called by Nexus (ABC License Server) after it generates the hash.
 * This endpoint is PUBLIC (@requires: 'any') — Nexus calls it without a
 * user session. Security is enforced in the implementation via:
 *   1. IP allowlist  (ABC_EGRESS_IPS env var)
 *   2. HMAC-SHA256 signature verification  (POSTBACK_SECRET + ABC_SIG_HEADER)
 *   3. Nonce validation  (nonce from ?n= query param must exist in nonce-store)
 *
 * Raw request body is captured BEFORE CDS parses it (in server.js bootstrap)
 * so the HMAC can be computed over the exact bytes Nexus sent.
 *
 * TODO (confirm with Ben/Nexus team):
 *   - Exact field name for the hash in the POST body  (assumed: "hash")
 *   - HMAC signature header name  → set ABC_SIG_HEADER env var
 *   - HMAC shared secret          → stored in BTP Credential Store → POSTBACK_SECRET
 *   - Egress IP(s) of Nexus server → set ABC_EGRESS_IPS env var (comma-separated)
 */
@path: '/nexus/callback'
@requires: 'any'
service CallbackService {

  /**
   * Receives the hash result from Nexus.
   * `hash` is the license hash value from the POST body.
   * The nonce is taken from the ?n= URL query parameter (not from the body).
   */
  action receive(hash : String) returns String;
}

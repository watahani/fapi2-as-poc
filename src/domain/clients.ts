/**
 * Registered client model (confidential clients only — FAPI2-GEN-3).
 *
 * Metadata is stored as JSON on the clients table and validated on load with
 * zod; unknown members are preserved but ignored. Field names follow the
 * OAuth Dynamic Client Registration / OIDC registration vocabulary so the
 * profile switches required by NFR-2 (auth method, sender-constraining) are
 * per-client data, not code.
 */
import { z } from "zod";
import type { JSONWebKeySet } from "jose";
import type { ClientRepository } from "../db/repositories/types.js";

const jwkSchema = z.object({ kty: z.string() }).passthrough();

const metadataSchema = z
  .object({
    // FAPI2-AUTHZ-8 / BCP-5: https only (loopback http is a native-app
    // exception we do not register in this PoC); exact-match comparison.
    redirect_uris: z.array(z.string().url()).min(1),
    // FAPI2-GEN-6: private_key_jwt (mTLS lands with P5).
    token_endpoint_auth_method: z.literal("private_key_jwt").default("private_key_jwt"),
    jwks: z.object({ keys: z.array(jwkSchema) }).optional(),
    // FAPI2 5.4.2 / DISC-CRYPTO: key material must be distributed over TLS.
    jwks_uri: z
      .string()
      .url()
      .refine((u) => new URL(u).protocol === "https:", "jwks_uri must use https")
      .optional(),
    grant_types: z
      .array(z.enum(["authorization_code", "refresh_token"]))
      .default(["authorization_code", "refresh_token"]),
    response_types: z.array(z.literal("code")).default(["code"]),
    // Space-delimited scopes the client may request (OAUTH-14).
    scope: z.string().default("openid"),
    id_token_signed_response_alg: z.literal("ES256").default("ES256"),
    // DPOP-11 / RFC 9449 §5.2. FAPI2-GEN-4 makes sender-constraining
    // mandatory, and DPoP is the only mechanism here, so default true.
    dpop_bound_access_tokens: z.boolean().default(true),
    // PAR-31 client metadata; the AS policy is global-required anyway.
    require_pushed_authorization_requests: z.boolean().default(true),
  })
  .passthrough();

export type ClientMetadata = z.infer<typeof metadataSchema>;

/** Validate registration metadata (used by loadClient and the seeder so a
 * non-compliant client is rejected at write time, not just read time). */
export function parseClientMetadata(metadata: unknown): ClientMetadata {
  const parsed = metadataSchema.safeParse(metadata);
  if (!parsed.success) {
    throw new InvalidClientMetadataError(parsed.error.message);
  }
  const md = parsed.data;
  for (const uri of md.redirect_uris) {
    const u = new URL(uri);
    if (u.protocol !== "https:" || u.hash !== "") {
      throw new InvalidClientMetadataError("redirect_uri must be https without fragment [FAPI2 5.3.2.2(8)]");
    }
  }
  if (!md.jwks && !md.jwks_uri) {
    throw new InvalidClientMetadataError("client needs jwks or jwks_uri for private_key_jwt [RFC7523 §3(9)]");
  }
  return md;
}

export interface Client {
  clientId: string;
  clientName: string | null;
  metadata: ClientMetadata;
}

export class InvalidClientMetadataError extends Error {}

/** Load + validate a registered client; null when unknown. */
export async function loadClient(repo: ClientRepository, clientId: string): Promise<Client | null> {
  if (!clientId) return null;
  const rec = await repo.findById(clientId);
  if (!rec) return null;
  const md = parseClientMetadata(rec.metadata);
  return { clientId: rec.clientId, clientName: rec.clientName, metadata: md };
}

/** RFC 9700 §2.1 / BCP-1: registered redirect URIs match by EXACT string
 * comparison — no prefix, subpath, or pattern matching. */
export function redirectUriRegistered(client: Client, redirectUri: string): boolean {
  return client.metadata.redirect_uris.includes(redirectUri);
}

/** Requested scope must be a subset of the client's registered scopes. */
export function scopeAllowed(client: Client, requestedScope: string): boolean {
  const allowed = new Set(client.metadata.scope.split(" ").filter(Boolean));
  return requestedScope.split(" ").filter(Boolean).every((s) => allowed.has(s));
}

export function clientJwksSource(client: Client): { jwks?: JSONWebKeySet; jwksUri?: string } {
  return {
    jwks: client.metadata.jwks as JSONWebKeySet | undefined,
    jwksUri: client.metadata.jwks_uri,
  };
}

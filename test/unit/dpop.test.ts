/**
 * DPoP proof verification unit tests (docs/REQUIREMENTS-P1.md DPOP-*),
 * exercising src/domain/dpop.ts directly against the in-memory jti store.
 */
import { describe, expect, it } from "vitest";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { loadConfig } from "../../src/config.js";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";
import { verifyDpopProof, issueNonce } from "../../src/domain/dpop.js";
import { OAuthError } from "../../src/domain/errors.js";
import { createDpopKey } from "../helpers/client.js";

const config = loadConfig({ STORAGE: "memory", ISSUER: "https://as.example.com" });
const HTU = "https://as.example.com/token";

function ctx(over: Partial<Parameters<typeof verifyDpopProof>[1]> = {}) {
  return { htm: "POST", htu: HTU, config, storage: createMemoryStorage(), ...over };
}

const expectDpopError = async (p: Promise<unknown>) => {
  const err = (await p.then(() => null, (e: unknown) => e)) as OAuthError | null;
  expect(err).toBeInstanceOf(OAuthError);
  return err as OAuthError;
};

describe("verifyDpopProof", () => {
  it("accepts a valid proof and returns the key thumbprint [RFC9449 §4.3, §6.1]", async () => {
    const dpop = await createDpopKey();
    const proof = await dpop.proof({ htm: "POST", htu: HTU });
    const { jkt } = await verifyDpopProof(proof, ctx());
    expect(jkt).toBe(dpop.jkt);
  });

  it("rejects multiple DPoP headers [RFC9449 §4.3 step 1]", async () => {
    const dpop = await createDpopKey();
    const proof = await dpop.proof({ htm: "POST", htu: HTU });
    const err = await expectDpopError(verifyDpopProof([proof, proof], ctx()));
    expect(err.error).toBe("invalid_dpop_proof");
  });

  it("rejects a missing proof [RFC9449 §5]", async () => {
    expect((await expectDpopError(verifyDpopProof(undefined, ctx()))).error).toBe("invalid_dpop_proof");
  });

  it("rejects a wrong typ [RFC9449 §4.2 / §11.5]", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk = await exportJWK(publicKey);
    const proof = await new SignJWT({ jti: "a", htm: "POST", htu: HTU, iat: Math.floor(Date.now() / 1000) })
      .setProtectedHeader({ alg: "ES256", typ: "jwt", jwk })
      .sign(privateKey);
    expect((await expectDpopError(verifyDpopProof(proof, ctx()))).error).toBe("invalid_dpop_proof");
  });

  it("rejects a jwk carrying a private key [RFC9449 §4.3 step 7]", async () => {
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    const privJwk = await exportJWK(privateKey); // includes d
    const proof = await new SignJWT({ jti: "a", htm: "POST", htu: HTU, iat: Math.floor(Date.now() / 1000) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: privJwk })
      .sign(privateKey);
    expect((await expectDpopError(verifyDpopProof(proof, ctx()))).error).toBe("invalid_dpop_proof");
  });

  it("rejects htm/htu mismatch [RFC9449 §4.3 steps 8-9]", async () => {
    const dpop = await createDpopKey();
    expect(
      (await expectDpopError(verifyDpopProof(await dpop.proof({ htm: "GET", htu: HTU }), ctx()))).error,
    ).toBe("invalid_dpop_proof");
    expect(
      (await expectDpopError(verifyDpopProof(await dpop.proof({ htm: "POST", htu: "https://as.example.com/other" }), ctx()))).error,
    ).toBe("invalid_dpop_proof");
  });

  it("accepts an htu with an explicit default port [RFC3986 §6.2.3]", async () => {
    const dpop = await createDpopKey();
    const proof = await dpop.proof({ htm: "POST", htu: "https://as.example.com:443/token" });
    const { jkt } = await verifyDpopProof(proof, ctx());
    expect(jkt).toBe(dpop.jkt);
  });

  it("rejects an iat outside the acceptance window [RFC9449 §11.1]", async () => {
    const dpop = await createDpopKey();
    const nowSec = Math.floor(Date.now() / 1000);
    const old = await dpop.proof({ htm: "POST", htu: HTU, iat: nowSec - 3600 });
    expect((await expectDpopError(verifyDpopProof(old, ctx()))).error).toBe("invalid_dpop_proof");
    const future = await dpop.proof({ htm: "POST", htu: HTU, iat: nowSec + 3600 });
    expect((await expectDpopError(verifyDpopProof(future, ctx()))).error).toBe("invalid_dpop_proof");
  });

  it("rejects jti replay within the window [RFC9449 §11.1]", async () => {
    const dpop = await createDpopKey();
    const storage = createMemoryStorage();
    const proof = await dpop.proof({ htm: "POST", htu: HTU, jti: "fixed" });
    await verifyDpopProof(proof, ctx({ storage }));
    expect((await expectDpopError(verifyDpopProof(proof, ctx({ storage })))).error).toBe("invalid_dpop_proof");
  });

  it("challenges with use_dpop_nonce when nonces are required [RFC9449 §8]", async () => {
    const nonceConfig = loadConfig({
      STORAGE: "memory",
      ISSUER: "https://as.example.com",
      DPOP_NONCE_REQUIRED: "true",
      DPOP_NONCE_SECRET: Buffer.alloc(32, 9).toString("base64url"),
    });
    const dpop = await createDpopKey();
    const storage = createMemoryStorage();
    const base = { htm: "POST", htu: HTU, config: nonceConfig, storage };
    // No nonce → use_dpop_nonce + DPoP-Nonce header.
    const err = await expectDpopError(
      verifyDpopProof(await dpop.proof({ htm: "POST", htu: HTU }), base),
    );
    expect(err.error).toBe("use_dpop_nonce");
    expect(err.headers["dpop-nonce"]).toBeTruthy();
    // Correct nonce → accepted.
    const nonce = issueNonce(dpop.jkt, "https://as.example.com/token", nonceConfig, new Date());
    const ok = await verifyDpopProof(await dpop.proof({ htm: "POST", htu: HTU, nonce }), {
      ...base,
      storage: createMemoryStorage(),
    });
    expect(ok.jkt).toBe(dpop.jkt);
  });
});

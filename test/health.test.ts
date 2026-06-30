import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/index.js";
import { closePool } from "../src/db/pool.js";

let app: FastifyInstance;

beforeAll(async () => {
  app = buildApp();
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await closePool();
});

describe("health endpoints", () => {
  it("GET /health returns 200 ok (liveness)", async () => {
    const res = await app.inject({ method: "GET", url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok" });
  });

  it("GET /healthz reports readiness without disclosing config", async () => {
    const res = await app.inject({ method: "GET", url: "/healthz" });
    const body = res.json() as { status: string; db: string };
    expect(["up", "down"]).toContain(body.db);
    // Must NOT leak internal config to unauthenticated callers.
    expect(body).not.toHaveProperty("issuer");
    expect(body).not.toHaveProperty("pdp");
    // 200 when the DB is reachable, 503 (degraded) otherwise.
    expect(res.statusCode).toBe(body.db === "up" ? 200 : 503);
  });
});
